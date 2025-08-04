package x509debug

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type Parsable[T any] interface {
	*T
	Parse(data *cryptobyte.String) error
}

// ParseSequenceOf parses an ASN.1 SequenceOf
// Tag should usually be asn1.Sequence, except when using implicit encoding.
func ParseSequenceOf[T any, PT Parsable[T]](data *cryptobyte.String, tag asn1.Tag) ([]T, error) {
	var ret []T

	var sequenceOf cryptobyte.String
	if !data.ReadASN1(&sequenceOf, tag) {
		return nil, fmt.Errorf("failed to parse %T", ret)
	}

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
