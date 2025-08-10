// Package x509debug is package for introspecting x509 certificates.
//
// It is lenient when parsing, which is bad for security but good for debugging.
// The parsed certificate can be serialized to JSON for use with other tools.
package x509debug

import (
	encoding_asn1 "encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

//	Certificate  ::=  SEQUENCE  {
//	  tbsCertificate     TBSCertificate,
//	  signatureAlgorithm AlgorithmIdentifier,
//	  signatureValue     BIT STRING  }
type Certificate struct {
	TbsCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     []byte
}

func ParseCertificate(der *cryptobyte.String) (*Certificate, error) {
	var certificate cryptobyte.String
	if !der.ReadASN1(&certificate, asn1.SEQUENCE) {
		return nil, errors.New("failed to read Certificate Sequence")
	}

	var tbsCertificate cryptobyte.String
	if !certificate.ReadASN1(&tbsCertificate, asn1.SEQUENCE) {
		return nil, errors.New("failed to read tbsCertificate")
	}

	signatureAlgorithm, err := ParseAlgorithmIdentifier(&certificate)

	var signatureValue []byte
	if !certificate.ReadASN1BitStringAsBytes(&signatureValue) {
		return nil, errors.New("failed to read signatureValue")
	}

	if !certificate.Empty() {
		return nil, errors.New("extra data after certificate")
	}

	parsedTBSCertificate, err := ParseTBSCertificate(&tbsCertificate)
	if err != nil {
		// TODO: We want to support partial parsing, and we want some way of handling that
		return nil, err
	}

	return &Certificate{
		TbsCertificate:     parsedTBSCertificate,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     signatureValue,
	}, nil
}

//	TBSCertificate  ::=  SEQUENCE  {
//		 version         [0]  EXPLICIT Version DEFAULT v1,
//		 serialNumber         CertificateSerialNumber,
//		 signature            AlgorithmIdentifier,
//		 issuer               Name,
//		 validity             Validity,
//		 subject              Name,
//		 subjectPublicKeyInfo SubjectPublicKeyInfo,
//		 issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//		                      -- If present, version MUST be v2 or v3
//		 subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//		                      -- If present, version MUST be v2 or v3
//		 extensions      [3]  EXPLICIT Extensions OPTIONAL
//		                      -- If present, version MUST be v3
//		 }
type TBSCertificate struct {
	Version              Version
	SerialNumber         CertificateSerialNumber
	Signature            AlgorithmIdentifier
	Issuer               RDNSequence
	Validity             Validity
	Subject              RDNSequence
	SubjectPublicKeyInfo SubjectPublicKeyInfo
	IssuerUniqueID       *UniqueIdentifier `json:",omitempty"`
	SubjectUniqueID      *UniqueIdentifier `json:",omitempty"`
	Extensions           Extensions
}

func ParseTBSCertificate(der *cryptobyte.String) (TBSCertificate, error) {
	var version uint
	if !der.ReadOptionalASN1Integer(&version, asn1.Tag(0).Constructed().ContextSpecific(), 0) {
		return TBSCertificate{}, errors.New("reading version")
	}

	var serialNumber []byte
	if !der.ReadASN1Integer(&serialNumber) {
		return TBSCertificate{}, errors.New("reading serial number")
	}

	signature, err := ParseAlgorithmIdentifier(der)
	if err != nil {
		return TBSCertificate{}, err
	}

	issuer, err := ParseRDNSequence(der)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("reading issuer: %w", err)
	}

	validity, err := ParseValidity(der)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("parsing validity: %w", err)
	}

	subject, err := ParseRDNSequence(der)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("reading subject: %w", err)
	}

	subjectPublicKeyInfo, err := ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("parsing SubjectPublicKeyInfo: %w", err)
	}

	issuerUniqueID, err := ParseUniqueIdentifier(der, 1)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("parsing issuer UniqueIdentifier: %w", err)
	}

	subjectUniqueID, err := ParseUniqueIdentifier(der, 2)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("parsing subject UniqueIdentifier: %w", err)
	}

	extensions, err := ParseExtensions(der)
	if err != nil {
		return TBSCertificate{}, fmt.Errorf("parsing extensions: %w", err)
	}

	if !der.Empty() {
		return TBSCertificate{}, errors.New("extra data after tbsCertificate")
	}

	return TBSCertificate{
		Version:              Version(version),
		SerialNumber:         serialNumber,
		Signature:            signature,
		Issuer:               issuer,
		Validity:             validity,
		Subject:              subject,
		SubjectPublicKeyInfo: subjectPublicKeyInfo,
		IssuerUniqueID:       issuerUniqueID,
		SubjectUniqueID:      subjectUniqueID,
		Extensions:           extensions,
	}, nil
}

//	AlgorithmIdentifier  ::=  SEQUENCE  {
//	    algorithm               OBJECT IDENTIFIER,
//	    parameters              ANY DEFINED BY algorithm OPTIONAL  }
//	                               -- contains a value of the type
//	                               -- registered for use with the
//	                               -- algorithm object identifier value
type AlgorithmIdentifier struct {
	Algorithm ObjectIdentifier
	Parameter any
}

func ParseAlgorithmIdentifier(der *cryptobyte.String) (AlgorithmIdentifier, error) {
	var algorithmIdentifier cryptobyte.String
	if !der.ReadASN1(&algorithmIdentifier, asn1.SEQUENCE) {
		return AlgorithmIdentifier{}, errors.New("failed to read AlgorithmIdentifier")
	}

	oid, err := ParseObjectIdentifier(&algorithmIdentifier)
	if err != nil {
		return AlgorithmIdentifier{}, err
	}

	// TODO: Parameters, based on the algorithm

	return AlgorithmIdentifier{
		Algorithm: oid,
	}, nil
}

type ObjectIdentifier encoding_asn1.ObjectIdentifier

func ParseObjectIdentifier(der *cryptobyte.String) (ObjectIdentifier, error) {
	var oid encoding_asn1.ObjectIdentifier
	if !der.ReadASN1ObjectIdentifier(&oid) {
		return ObjectIdentifier{}, errors.New("failed to read OID")
	}
	return ObjectIdentifier(oid), nil
}

func (oid *ObjectIdentifier) Parse(der *cryptobyte.String) error {
	o, err := ParseObjectIdentifier(der)
	if err != nil {
		return err
	}
	*oid = o
	return nil
}

func (oid *ObjectIdentifier) String() string {
	return encoding_asn1.ObjectIdentifier(*oid).String()
}

func (oid *ObjectIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(oid.String())
}

// Version ::= INTEGER {v1(0), v2(1), v3(2)}
type Version uint

func (v Version) String() string {
	if v > 2 {
		return fmt.Sprintf("unknown(%d)", v)
	}
	return fmt.Sprintf("v%d(%d)", v+1, v)
}

// CertificateSerialNumber  ::=  INTEGER
type CertificateSerialNumber []byte

func (serial CertificateSerialNumber) String() string {
	return hex.EncodeToString(serial)
}

func (serial CertificateSerialNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(serial.String())
}

func ParseRDNSequence(der *cryptobyte.String) (RDNSequence, error) {
	var ret RDNSequence
	err := (&ret).Parse(der)
	return ret, err
}

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
type RDNSequence []RelativeDistinguishedName

func (rdns *RDNSequence) Parse(data *cryptobyte.String) error {
	parsed, err := ParseSequenceOf[RelativeDistinguishedName](data)
	if err != nil {
		return err
	}
	*rdns = parsed
	return nil
}

func (rdns *RDNSequence) String() string {
	var ret strings.Builder
	for _, rdn := range *rdns {
		for _, atv := range rdn {
			if ret.Len() > 0 {
				ret.WriteRune(',')
			}
			ret.WriteString(atv.Type.String())
			ret.WriteRune('=')
			ret.WriteString(string(atv.Value))
		}
	}
	return ret.String()
}

// RelativeDistinguishedName ::=
//
//	SET SIZE (1..MAX) OF AttributeTypeAndValue
type RelativeDistinguishedName []AttributeTypeAndValue

func (rdn *RelativeDistinguishedName) Parse(data *cryptobyte.String) error {
	parsed, err := ParseSetOf[AttributeTypeAndValue](data)
	if err != nil {
		return err
	}

	*rdn = parsed
	return nil
}

// AttributeTypeAndValue ::= SEQUENCE {
// type     AttributeType,
// value    AttributeValue }
// This represents an ATV as its oid and its raw value
type AttributeTypeAndValue struct {
	Type  ObjectIdentifier
	Value String
}

func (atv *AttributeTypeAndValue) Parse(data *cryptobyte.String) error {
	oid, s, err := ParseSequence2[ObjectIdentifier, String](data)
	if err != nil {
		return err
	}

	atv.Type = oid
	atv.Value = s
	return nil
}

//	Validity ::= SEQUENCE {
//	  notBefore      Time,
//	  notAfter       Time }
type Validity struct {
	NotBefore Time
	NotAfter  Time
}

func ParseValidity(der *cryptobyte.String) (Validity, error) {
	notBefore, notAfter, err := ParseSequence2[Time, Time](der)
	if err != nil {
		return Validity{}, err
	}

	return Validity{
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, nil
}

//	Time ::= CHOICE {
//	  utcTime        UTCTime,
//	  generalTime    GeneralizedTime }
type Time struct {
	Tag  asn1.Tag
	Time time.Time
}

func (t *Time) Parse(der *cryptobyte.String) error {
	if der.PeekASN1Tag(asn1.UTCTime) {
		var utcTime time.Time
		if !der.ReadASN1UTCTime(&utcTime) {
			return errors.New("failed to parse UTCTime")
		}
		*t = Time{asn1.UTCTime, utcTime}
		return nil
	}
	if der.PeekASN1Tag(asn1.GeneralizedTime) {
		var generalizedTime time.Time
		if !der.ReadASN1GeneralizedTime(&generalizedTime) {
			return errors.New("failed to parse GeneralizedTime")
		}
		*t = Time{asn1.GeneralizedTime, generalizedTime}
		return nil
	}
	return errors.New("failed to parse time")
}

//	SubjectPublicKeyInfo  ::=  SEQUENCE  {
//	    algorithm            AlgorithmIdentifier,
//	    subjectPublicKey     BIT STRING  }
type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey []byte
}

func ParseSubjectPublicKeyInfo(der *cryptobyte.String) (SubjectPublicKeyInfo, error) {
	var subjectPublicKeyInfo cryptobyte.String
	if !der.ReadASN1(&subjectPublicKeyInfo, asn1.SEQUENCE) {
		return SubjectPublicKeyInfo{}, errors.New("failed to read SubjectPublicKeyInfo")
	}

	algo, err := ParseAlgorithmIdentifier(&subjectPublicKeyInfo)
	if err != nil {
		return SubjectPublicKeyInfo{}, fmt.Errorf("parsing SubjectPublicKeyInfo Algorithm: %w", err)
	}

	var subjectPublicKey []byte
	if !subjectPublicKeyInfo.ReadASN1BitStringAsBytes(&subjectPublicKey) {
		return SubjectPublicKeyInfo{}, errors.New("failed to read SubjectPublicKeyInfo public key")
	}

	return SubjectPublicKeyInfo{
		Algorithm:        algo,
		SubjectPublicKey: subjectPublicKey,
	}, nil
}

// UniqueIdentifier  ::=  BIT STRING
type UniqueIdentifier []byte

func ParseUniqueIdentifier(der *cryptobyte.String, tag uint8) (*UniqueIdentifier, error) {
	var uniqueIdentifier cryptobyte.String
	var hasUniqueIdentifier bool

	if !der.ReadOptionalASN1(&uniqueIdentifier, &hasUniqueIdentifier, asn1.Tag(tag).ContextSpecific()) {
		return nil, errors.New("failed to read UniqueIdentifier")
	}

	if hasUniqueIdentifier {
		// TODO
		return &UniqueIdentifier{}, nil
	}

	return nil, nil
}

const (
	OtherName                 = 0
	RFC822Name                = 1
	DNSName                   = 2
	X400Address               = 3
	DirectoryName             = 4
	EDIPartyName              = 5
	UniformResourceIdentifier = 6
	IPAddress                 = 7
	RegisteredID              = 8
)

type GeneralName struct {
	Tag   asn1.Tag
	Value string
}

func (gn *GeneralName) Parse(der *cryptobyte.String) error {
	v, err := ParseGeneralName(der, false)
	if err != nil {
		return err
	}
	*gn = v
	return nil
}

// ParseGeneralName parses a GeneralName as defined in RFC5280 4.2.1.6
// Tag is the context-sensitive tag from the GeneralName CHOICE, and the constants above.
// TODO: Is a string the best way to represent these names?
func ParseGeneralName(der *cryptobyte.String, useIPCIDR bool) (GeneralName, error) {
	var data cryptobyte.String
	var tag asn1.Tag
	if !der.ReadAnyASN1(&data, &tag) {
		return GeneralName{}, fmt.Errorf("failed to read general name from %s", hex.EncodeToString(*der))
	}

	// remove context-specific bit
	tag = tag ^ 0x80

	var value string

	switch tag {
	case RFC822Name, DNSName, UniformResourceIdentifier:
		// IA5String
		value = string(data)
	case IPAddress:
		if useIPCIDR {
			if len(data) != net.IPv4len*2 && len(data) != net.IPv6len*2 {
				return GeneralName{}, fmt.Errorf("invalid IP address and mask length: %d", len(data))
			}
			// In name constraints, IP Address names have a mask included
			ipnet := net.IPNet{
				IP:   net.IP(data[len(data)/2:]),
				Mask: net.IPMask(data[:len(data)/2]),
			}
			value = ipnet.String()
		} else {
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				return GeneralName{}, fmt.Errorf("wrong length of IP address: %d", len(data))
			}
			// Octet String
			value = net.IP(data).String()
		}
	case asn1.Tag(DirectoryName).Constructed():
		rdns, err := ParseRDNSequence(&data)
		if err != nil {
			return GeneralName{}, err
		}
		value = rdns.String()
	default:
		value = hex.EncodeToString(data)
	}

	return GeneralName{
		Tag:   tag,
		Value: value,
	}, nil
}
