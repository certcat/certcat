package x509debug

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type Parsable interface {
	// Parse data into this type
	Parse(data *cryptobyte.String) error
}

// ParseSequenceOf parses an ASN.1 SequenceOf
// Tag should usually be asn1.Sequence, except when using implicit encoding.
func ParseSequenceOf[T any, PT interface {
	*T
	Parsable
}](data *cryptobyte.String, tag asn1.Tag) ([]T, error) {
	var sequenceOf cryptobyte.String
	if !data.ReadASN1(&sequenceOf, tag) {
		return nil, errors.New("failed to parse ASN.1 sequence")
	}

	var ret []T

	for !sequenceOf.Empty() {
		var t T
		var pt PT = &t
		if err := pt.Parse(&sequenceOf); err != nil {
			return nil, err
		}
		ret = append(ret, t)
	}

	return ret, nil
}
