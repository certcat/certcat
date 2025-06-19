package x509debug

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// TestCertJSON makes sure that the JSON generated from a certificate object matches expected JSON
func TestCertJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
	}{
		{"ipcert"},
		{"testcert"},
		{"wikipedia"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.name+".pem"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			cert := cryptobyte.String(block.Bytes)
			parsed, err := ParseCertificate(&cert)
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := json.MarshalIndent(parsed, "", "\t")
			if err != nil {
				t.Fatal(err)
			}

			expectedJSON, err := os.ReadFile(filepath.Join("testdata", tc.name+".json"))
			if err != nil {
				t.Fatal(err)
			}

			var got, expected interface{}
			if err := json.Unmarshal(gotJSON, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(expectedJSON, &expected); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, expected) {
				// Write out what we got, for easier diffing
				_ = os.WriteFile(filepath.Join("testdata", tc.name+".got.json"), gotJSON, 0644)
				fmt.Println("Got:")
				fmt.Println(string(gotJSON))
				fmt.Println("Expected:")
				fmt.Println(string(expectedJSON))
				t.Fatal("JSON does not match expected")
			}
		})
	}
}
