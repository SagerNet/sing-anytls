package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
)

type ClientOptions struct {
	Password                 string
	ClientMetadata           string
	DialOut                  DialOutFunc
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	DisableReuse             bool
	Logger                   logger.ContextLogger
}

type Client struct {
	password       [passwordLen]byte
	clientMetadata string
	dialOut        DialOutFunc
	logger         logger.ContextLogger
	padding        common.TypedValue[*paddingFactory]

	idleCheckInterval time.Duration
	idleTimeout       time.Duration
	minIdleSession    int
	disableReuse      bool

	access       sync.Mutex
	closed       bool
	sessions     map[*session]struct{}
	idleSessions list.List[*session]
	idleTimer    *time.Timer
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Password == "" {
		return nil, ErrMissingPassword
	}
	if options.DialOut == nil {
		return nil, ErrMissingDialer
	}
	factory, err := newPaddingFactory(DefaultPaddingScheme)
	if err != nil {
		return nil, err
	}
	client := &Client{
		password:          sha256.Sum256([]byte(options.Password)),
		clientMetadata:    options.ClientMetadata,
		dialOut:           options.DialOut,
		logger:            options.Logger,
		idleCheckInterval: options.IdleSessionCheckInterval,
		idleTimeout:       options.IdleSessionTimeout,
		minIdleSession:    options.MinIdleSession,
		disableReuse:      options.DisableReuse,
		sessions:          make(map[*session]struct{}),
	}
	if client.logger == nil {
		client.logger = logger.NOP()
	}
	if client.idleCheckInterval <= minimumIdleSessionInterval {
		client.idleCheckInterval = defaultIdleSessionCheckInterval
	}
	if client.idleTimeout <= minimumIdleSessionInterval {
		client.idleTimeout = defaultIdleSessionTimeout
	}
	client.padding.Store(factory)
	return client, nil
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, E.New("anytls: invalid destination: ", destination)
	}
	if len(destination.Fqdn) > 255 {
		return nil, E.New("anytls: domain too long: ", destination.Fqdn)
	}
	idle := c.takeIdleSession()
	if idle != nil {
		opened, err := idle.openStream(destination)
		if err == nil && !idle.IsClosed() {
			return opened, nil
		}
		if opened != nil {
			opened.Close()
		}
		idle.Close()
	}
	created, err := c.createSession(ctx)
	if err != nil {
		return nil, err
	}
	opened, err := created.openStream(destination)
	if err != nil {
		created.Close()
		return nil, err
	}
	return opened, nil
}

func (c *Client) createSession(ctx context.Context) (*session, error) {
	c.access.Lock()
	closed := c.closed
	c.access.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}
	paddingLen := c.padding.Load().GenerateHandshakePaddingSize()
	request := buf.NewSize(passwordLen + 2 + paddingLen)
	common.Must1(request.Write(c.password[:]))
	binary.BigEndian.PutUint16(request.Extend(2), uint16(paddingLen))
	common.Must(request.WriteZeroN(paddingLen))
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		conn.SetWriteDeadline(deadline)
	}
	_, err = conn.Write(request.Bytes())
	request.Release()
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "anytls: write request")
	}
	conn.SetWriteDeadline(time.Time{})
	created := newClientSession(c, conn)
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		created.Close()
		return nil, net.ErrClosed
	}
	c.sessions[created] = struct{}{}
	c.access.Unlock()
	go func() {
		loopErr := created.readLoop()
		created.Close()
		if !E.IsClosedOrCanceled(loopErr) {
			c.logger.Debug(E.Cause(loopErr, "anytls: session closed"))
		}
	}()
	return created, nil
}

func (c *Client) takeIdleSession() *session {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	element := c.idleSessions.Front()
	if element == nil {
		return nil
	}
	idle := c.idleSessions.Remove(element)
	idle.element = nil
	return idle
}

func (c *Client) releaseSession(released *session) {
	if c.disableReuse {
		released.Close()
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	if released.IsClosed() || c.closed {
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		delete(c.sessions, released)
		return
	}
	if released.element == nil {
		released.idleSince = time.Now()
		released.element = c.idleSessions.PushFront(released)
		if c.idleTimer == nil {
			c.idleTimer = time.AfterFunc(c.idleCheckInterval, c.cleanupIdleSessions)
		}
	}
}

func (c *Client) removeSession(removed *session) {
	c.access.Lock()
	defer c.access.Unlock()
	if removed.element != nil {
		c.idleSessions.Remove(removed.element)
		removed.element = nil
	}
	delete(c.sessions, removed)
}

func (c *Client) cleanupIdleSessions() {
	var expired []*session
	c.access.Lock()
	if c.closed {
		c.idleTimer = nil
		c.access.Unlock()
		return
	}
	deadline := time.Now().Add(-c.idleTimeout)
	for element := c.idleSessions.Back(); element != nil && c.idleSessions.Len() > c.minIdleSession; {
		previous := element.Prev()
		idle := element.Value
		if !idle.idleSince.Before(deadline) {
			break
		}
		if idle.hasStreams() {
			element = previous
			continue
		}
		c.idleSessions.Remove(element)
		idle.element = nil
		expired = append(expired, idle)
		element = previous
	}
	if c.idleSessions.Len() > 0 {
		c.idleTimer.Reset(c.idleCheckInterval)
	} else {
		c.idleTimer = nil
	}
	c.access.Unlock()
	for _, idle := range expired {
		idle.Close()
	}
}

func (c *Client) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	if c.idleTimer != nil {
		c.idleTimer.Stop()
		c.idleTimer = nil
	}
	sessions := make([]*session, 0, len(c.sessions))
	for closing := range c.sessions {
		closing.element = nil
		sessions = append(sessions, closing)
	}
	clear(c.sessions)
	c.idleSessions.Init()
	c.access.Unlock()
	var err error
	for _, closing := range sessions {
		err = E.Errors(err, closing.Close())
	}
	return err
}
