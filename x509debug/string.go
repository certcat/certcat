package x509debug

import (
	encoding_asn1 "encoding/asn1"
	"errors"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var NotAString = errors.New("unknown string type")

type String string

func (s *String) Parse(data *cryptobyte.String) error {
	var out cryptobyte.String
	var tag asn1.Tag
	if !data.ReadAnyASN1(&out, &tag) {
		return errors.New("reading string")
	}

	asdf, err := parseString(tag, out)
	if err != nil {
		return err
	}

	*s = String(asdf)
	return nil
}

// parseString gives us a Golang string out of ASN.1
func parseString(tag asn1.Tag, data cryptobyte.String) (string, error) {
	switch tag {
	case encoding_asn1.TagBMPString:
		return parseBMPString(data)
	case asn1.PrintableString, asn1.IA5String, asn1.UTF8String:
		// TODO: Make sure the semantics of each string type is right
		return string(data), nil
	default:
		return "", NotAString
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
