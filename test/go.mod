module github.com/sagernet/sing-anytls/test

go 1.24.0

require (
	github.com/anytls/sing-anytls v0.0.11
	github.com/sagernet/sing v0.8.14
	github.com/sagernet/sing-anytls v0.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/sagernet/sing-anytls => ../
