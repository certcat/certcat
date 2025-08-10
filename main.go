// package main entry point for the CLI
// This is at the top-level to make it easy to `go run` or `go install`
package main

import (
	"github.com/certcat/certcat/cmd/cli"
)

func main() {
	cli.Execute()
}
