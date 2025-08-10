// package main
//
// This is the Certcat.dev server backend entry point.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "certcat-server",
	Short: "Run the server",
}

func main() {
	err := serverCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
