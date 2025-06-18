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

func TestCertJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
	}{
		{"testcert"},
		{"ipcert"},
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
				fmt.Println("Got:")
				fmt.Println(string(gotJSON))
				fmt.Println("Expected:")
				fmt.Println(string(expectedJSON))
				t.Fatal("JSON does not match expected")
			}
		})
	}
}
