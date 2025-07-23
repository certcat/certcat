package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/certcat/certcat/files/pem"
	"github.com/certcat/certcat/x509debug"
	"github.com/spf13/cobra"
)

// printCmd represents the print command
var printCmd = &cobra.Command{
	Args: cobra.MinimumNArgs(1),
	RunE: runPrint,
	Use:  "print [flags] filenames...",
	Long: `Print a certificate.

Takes a path to a certificate and prints out its contents.`,
}

func init() {
	rootCmd.AddCommand(printCmd)

	printCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	printCmd.Flags().StringP("format", "f", "PEM", "Input file format")
}

func runPrint(cmd *cobra.Command, files []string) error {
	certs := make(map[string][]*x509debug.Certificate)
	for _, file := range files {
		read, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		these, err := pem.LoadAll(read)
		if err != nil {
			return err
		}
		certs[file] = these
	}

	// TODO: This really is just a placeholder until I add real output.
	d, e := json.MarshalIndent(certs, "", "  ")
	if e != nil {
		return e
	}
	fmt.Println(string(d))

	return nil
}
