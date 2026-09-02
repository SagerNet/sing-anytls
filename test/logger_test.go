package test

import (
	"context"
	"os"

	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
)

type printLogger struct {
	prefix string
}

func (l printLogger) print(args ...any) {
	os.Stderr.WriteString(l.prefix + F.ToString(args...) + "\n")
}

func (l printLogger) Trace(args ...any) { l.print(args...) }
func (l printLogger) Debug(args ...any) { l.print(args...) }
func (l printLogger) Info(args ...any)  { l.print(args...) }
func (l printLogger) Warn(args ...any)  { l.print(args...) }
func (l printLogger) Error(args ...any) { l.print(args...) }
func (l printLogger) Fatal(args ...any) { l.print(args...) }
func (l printLogger) Panic(args ...any) { l.print(args...) }

func (l printLogger) TraceContext(ctx context.Context, args ...any) { l.print(args...) }
func (l printLogger) DebugContext(ctx context.Context, args ...any) { l.print(args...) }
func (l printLogger) InfoContext(ctx context.Context, args ...any)  { l.print(args...) }
func (l printLogger) WarnContext(ctx context.Context, args ...any)  { l.print(args...) }
func (l printLogger) ErrorContext(ctx context.Context, args ...any) { l.print(args...) }
func (l printLogger) FatalContext(ctx context.Context, args ...any) { l.print(args...) }
func (l printLogger) PanicContext(ctx context.Context, args ...any) { l.print(args...) }

func testLogger(prefix string) logger.ContextLogger {
	if os.Getenv("ANYTLS_TEST_LOG") == "" {
		return logger.NOP()
	}
	return printLogger{prefix: prefix}
}
