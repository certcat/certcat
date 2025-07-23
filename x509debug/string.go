package x509debug

import (
	encoding_asn1 "encoding/asn1"
	"errors"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// parseString gives us a Golang string out of ASN.1
func parseString(tag asn1.Tag, data cryptobyte.String) (string, error) {
	switch tag {
	case encoding_asn1.TagBMPString:
		return parseBMPString(data)
	case asn1.IA5String, asn1.UTF8String:
		return string(data), nil
	default:
		return "", errors.New("unknown ASN.1 string tag")
	}
}

// parseBMPString parses a utf-16 bmpString. Taken from pkcs12.
func parseBMPString(bmpString cryptobyte.String) (string, error) {
	if len(bmpString)%2 != 0 {
		return "", errors.New("odd-length BMP string")
	}

	// Strip terminator if present.
	if l := len(bmpString); l >= 2 && bmpString[l-1] == 0 && bmpString[l-2] == 0 {
		bmpString = bmpString[:l-2]
	}

	s := make([]uint16, 0, len(bmpString)/2)
	for len(bmpString) > 0 {
		s = append(s, uint16(bmpString[0])<<8+uint16(bmpString[1]))
		bmpString = bmpString[2:]
	}

	return string(utf16.Decode(s)), nil
}
