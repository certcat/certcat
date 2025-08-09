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

func ParseSequenceOf[T any, PT Parsable[T]](data *cryptobyte.String) ([]T, error) {
	return ParseSequenceOfTagged[T, PT](data, asn1.SEQUENCE)
}

// ParseSequenceOfTagged parses an ASN.1 SequenceOf with a custom tag when using implicit encoding.
func ParseSequenceOfTagged[T any, PT Parsable[T]](data *cryptobyte.String, tag asn1.Tag) ([]T, error) {
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

// ParseSequence2 parses a SEQUENCE of two values.
func ParseSequence2[T1 any, T2 any, PT1 Parsable[T1], PT2 Parsable[T2]](data *cryptobyte.String) (T1, T2, error) {
	var r1 T1
	var r2 T2

	var sequence cryptobyte.String
	if !data.ReadASN1(&sequence, asn1.SEQUENCE) {
		return r1, r2, fmt.Errorf("failed to parse sequence {%T %T}", r1, r2)
	}

	var pt1 PT1 = &r1
	err := pt1.Parse(&sequence)
	if err != nil {
		return r1, r2, fmt.Errorf("parsing %T: %w", r1, err)
	}

	var pt2 PT2 = &r2
	err = pt2.Parse(&sequence)
	if err != nil {
		return r1, r2, fmt.Errorf("parsing %T: %w", r2, err)
	}

	if !sequence.Empty() {
		return r1, r2, fmt.Errorf("trailing data after {%T %T}", r1, r2)
	}

	return r1, r2, nil
}
