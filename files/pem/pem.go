package pem

import (
	"encoding/pem"

	"github.com/certcat/certcat/x509debug"
	"golang.org/x/crypto/cryptobyte"
)

// LoadAll x509 certificates from content
func LoadAll(content []byte) ([]*x509debug.Certificate, error) {
	var block *pem.Block
	var certs []*x509debug.Certificate

	for {
		block, content = pem.Decode(content)
		if block == nil {
			return certs, nil
		}
		if block.Type != "CERTIFICATE" {
			// TODO: May want to support loading cert + key files too
			continue
		}

		der := cryptobyte.String(block.Bytes)
		certificate, err := x509debug.ParseCertificate(&der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, certificate)
	}
}
