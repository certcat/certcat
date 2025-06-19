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

func (oid ObjectIdentifier) String() string {
	return encoding_asn1.ObjectIdentifier(oid).String()
}

func (oid ObjectIdentifier) MarshalJSON() ([]byte, error) {
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

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
type RDNSequence string

var DNNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.6":                    "C",
	"2.5.4.9":                    "STREET",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}

func RDNString(atv AttributeTypeAndValue) string {
	name, ok := DNNames[atv.Type.String()]
	if !ok {
		name = atv.Type.String()
	}
	if atv.Tag == asn1.PrintableString || atv.Tag == asn1.UTF8String {
		return name + "=" + string(atv.Value)
	}

	// Unknown value type, return as hex
	return fmt.Sprintf("%s=%d:%s", name, atv.Tag, hex.EncodeToString(atv.Value))
}

// ParseRDNSequence turns the DER RDNs into a string, per RFC4514 representation
func ParseRDNSequence(der *cryptobyte.String) (RDNSequence, error) {
	var rdnSequence cryptobyte.String
	if !der.ReadASN1(&rdnSequence, asn1.SEQUENCE) {
		return "", errors.New("failed to read RDNSequence")
	}

	var ret strings.Builder

	for !rdnSequence.Empty() {
		var atvSet cryptobyte.String
		if !rdnSequence.ReadASN1(&atvSet, asn1.SET) {
			return "", errors.New("failed to read ATVSet")
		}
		for !atvSet.Empty() {
			atv, err := ParseATV(&atvSet)
			if err != nil {
				return "", err
			}
			if ret.Len() > 0 {
				ret.WriteRune(',')
			}
			ret.WriteString(RDNString(atv))
		}
	}

	return RDNSequence(ret.String()), nil
}

// AttributeTypeAndValue ::= SEQUENCE {
// type     AttributeType,
// value    AttributeValue }
// This represents an ATV as its oid and its raw value
type AttributeTypeAndValue struct {
	Type  ObjectIdentifier
	Tag   asn1.Tag
	Value cryptobyte.String
}

func ParseATV(der *cryptobyte.String) (AttributeTypeAndValue, error) {
	var atv cryptobyte.String
	if !der.ReadASN1(&atv, asn1.SEQUENCE) {
		return AttributeTypeAndValue{}, errors.New("failed to read ATV")
	}

	oid, err := ParseObjectIdentifier(&atv)
	if err != nil {
		return AttributeTypeAndValue{}, err
	}

	ret := AttributeTypeAndValue{
		Type: oid,
	}
	if !atv.ReadAnyASN1(&ret.Value, &ret.Tag) {
		return AttributeTypeAndValue{}, errors.New("failed to read ATV Value")
	}
	return ret, nil
}

//	Validity ::= SEQUENCE {
//	  notBefore      Time,
//	  notAfter       Time }
type Validity struct {
	NotBefore Time
	NotAfter  Time
}

func ParseValidity(der *cryptobyte.String) (Validity, error) {
	var validity cryptobyte.String
	if !der.ReadASN1(&validity, asn1.SEQUENCE) {
		return Validity{}, errors.New("failed to read Validity")
	}

	notBefore, err := ParseTime(&validity)
	if err != nil {
		return Validity{}, fmt.Errorf("parsing NotBefore: %w", err)
	}

	notAfter, err := ParseTime(&validity)
	if err != nil {
		return Validity{}, fmt.Errorf("parsing NotAfter: %w", err)
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

func ParseTime(der *cryptobyte.String) (Time, error) {
	var t time.Time
	if der.PeekASN1Tag(asn1.UTCTime) {
		if !der.ReadASN1UTCTime(&t) {
			return Time{}, errors.New("failed to parse UTCTime")
		}
		return Time{asn1.UTCTime, t}, nil
	}
	if der.PeekASN1Tag(asn1.GeneralizedTime) {
		if !der.ReadASN1GeneralizedTime(&t) {
			return Time{}, errors.New("failed to parse GeneralizedTime")
		}
		return Time{asn1.GeneralizedTime, t}, nil
	}
	return Time{}, errors.New("failed to parse time")
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

// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
type Extensions []Extension

func ParseExtensions(der *cryptobyte.String) (Extensions, error) {
	var extensions cryptobyte.String
	var hasExtensions bool
	var tag = asn1.Tag(3).Constructed().ContextSpecific()
	if !der.ReadOptionalASN1(&extensions, &hasExtensions, tag) {
		return nil, errors.New("failed to read Extensions")
	}

	var parsedExtensions Extensions

	if hasExtensions {
		if !extensions.ReadASN1(&extensions, asn1.SEQUENCE) {
			return nil, errors.New("failed to read Extensions")
		}

		for !extensions.Empty() {
			ext, err := ParseExtension(&extensions)
			if err != nil {
				return nil, fmt.Errorf("parsing extensions: %w", err)
			}
			parsedExtensions = append(parsedExtensions, ext)
		}
	}

	return parsedExtensions, nil
}

//	Extension  ::=  SEQUENCE  {
//	    extnID      OBJECT IDENTIFIER,
//	    critical    BOOLEAN DEFAULT FALSE,
//	    extnValue   OCTET STRING
//	                -- contains the DER encoding of an ASN.1 value
//	                -- corresponding to the extension type identified
//	                -- by extnID
//	    }
type Extension struct {
	ExtnId    ObjectIdentifier
	Critical  bool
	ExtnValue any // TBD interface?
}

func ParseExtension(der *cryptobyte.String) (Extension, error) {
	var extension cryptobyte.String
	if !der.ReadASN1(&extension, asn1.SEQUENCE) {
		return Extension{}, errors.New("failed to read Extension")
	}

	extnID, err := ParseObjectIdentifier(&extension)
	if err != nil {
		return Extension{}, fmt.Errorf("parsing Extension OID: %w", err)
	}

	critical := false
	if extension.PeekASN1Tag(asn1.BOOLEAN) {
		if !extension.ReadASN1Boolean(&critical) {
			return Extension{}, errors.New("failed to read critical bit")
		}
	}

	var extnValue cryptobyte.String
	if !extension.ReadASN1(&extnValue, asn1.OCTET_STRING) {
		return Extension{}, errors.New("failed to read extension value")
	}

	parsed, err := ParseExtensionValue(extnID, extnValue)
	if err != nil {
		return Extension{}, fmt.Errorf("parsing extension value: %w", err)
	}

	return Extension{
		ExtnId:    extnID,
		Critical:  critical,
		ExtnValue: parsed,
	}, nil
}

func ParseExtensionValue(oid ObjectIdentifier, val cryptobyte.String) (any, error) {
	var ret any
	var err error

	switch oid.String() {
	case "1.3.6.1.4.1.11129.2.4.2":
		ret, err = ParseSCTExtension(&val)
	case "1.3.6.1.4.1.11129.2.4.3":
		ret, err = ParsePrecertificatePoisonExtension(&val)
	case "1.3.6.1.5.5.7.1.1":
		ret, err = ParseAIAExtension(&val)
	case "1.3.6.1.5.5.7.1.11":
		ret, err = ParseSIAExtension(&val)
	case "1.3.6.1.5.5.7.1.24":
		ret, err = ParseTLSFeatureExtension(&val)
	case "2.5.29.9":
		ret, err = ParseSDAExtension(&val)
	case "2.5.29.14":
		ret, err = ParseSKIExtension(&val)
	case "2.5.29.15":
		ret, err = ParseKeyUsageExtension(&val)
	case "2.5.29.17":
		ret, err = ParseSANExtension(&val)
	case "2.5.29.18":
		ret, err = ParseIANExtension(&val)
	case "2.5.29.19":
		ret, err = ParseBasicConstraintsExtension(&val)
	case "2.5.29.30":
		ret, err = ParseNameConstraintsExtension(&val)
	case "2.5.29.31":
		ret, err = ParseCRLDPExtension(&val)
	case "2.5.29.32":
		ret, err = ParseCertPoliciesExtension(&val)
	case "2.5.29.33":
		ret, err = ParsePolicyMappingsExtension(&val)
	case "2.5.29.35":
		ret, err = ParseAKIExtension(&val)
	case "2.5.29.36":
		ret, err = ParsePolicyConstraintsExtension(&val)
	case "2.5.29.37":
		ret, err = ParseExtKeyUsageExtension(&val)
	case "2.5.29.46":
		ret, err = ParseFreshestCRLExtension(&val)
	case "2.5.29.54":
		ret, err = ParseInhibitAnyPolicyExtension(&val)
	default:
		return UnknownExtension{
			Raw: val,
		}, err
	}

	//if !val.Empty() {
	//	return nil, fmt.Errorf("Data after extension %s: %s", oid.String(), hex.EncodeToString(val))
	//}

	return ret, err
}

type UnknownExtension struct {
	Raw []byte
}

type SCTExtension struct {
	Raw []byte
}

// ParseAKIExtension as described in RFC5280 4.2.1.1
func ParseAKIExtension(der *cryptobyte.String) (string, error) {
	//    AuthorityKeyIdentifier ::= SEQUENCE {
	//      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	//      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	//      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
	return "AKI", nil
}

// ParseSKIExtension as described in RFC5280 4.2.1.2
func ParseSKIExtension(der *cryptobyte.String) (string, error) {
	//    SubjectKeyIdentifier ::= KeyIdentifier
	return "SKI", nil
}

type KeyUsage int

// ParseKeyUsageExtension as described in RFC5280 4.2.1.3
func ParseKeyUsageExtension(der *cryptobyte.String) ([]KeyUsage, error) {
	//       KeyUsage ::= BIT STRING {
	//           digitalSignature        (0),
	//           nonRepudiation          (1), -- recent editions of X.509 have
	//                                -- renamed this bit to contentCommitment
	//           keyEncipherment         (2),
	//           dataEncipherment        (3),
	//           keyAgreement            (4),
	//           keyCertSign             (5),
	//           cRLSign                 (6),
	//           encipherOnly            (7),
	//           decipherOnly            (8) }

	var bits encoding_asn1.BitString
	if !der.ReadASN1BitString(&bits) {
		return nil, errors.New("failed to read keyusage")
	}

	var usages []KeyUsage

	for i := range 9 {
		if bits.At(i) != 0 {
			usages = append(usages, KeyUsage(i))
		}
	}

	return usages, nil
}

// ParseCertPoliciesExtension as described in RFC5280 4.2.1.4
func ParseCertPoliciesExtension(der *cryptobyte.String) (string, error) {
	return "CertPolicies", nil
}

// ParsePolicyMappingsExtension as described in RFC5280 4.2.1.5
func ParsePolicyMappingsExtension(der *cryptobyte.String) (string, error) {
	return "PolicyMappings", nil
}

// ParseSANExtension as described in RFC5280 4.2.1.6
func ParseSANExtension(der *cryptobyte.String) ([]GeneralName, error) {
	var sans cryptobyte.String
	if !der.ReadASN1(&sans, asn1.SEQUENCE) {
		return nil, errors.New("failed to parse SAN extension")
	}

	var ret []GeneralName

	for !sans.Empty() {
		name, err := ParseGeneralName(&sans)
		if err != nil {
			return nil, fmt.Errorf("parsing SAN: %w", err)
		}

		ret = append(ret, name)
	}

	return ret, nil
}

// ParseIANExtension as described in RFC5280 4.2.1.7
func ParseIANExtension(der *cryptobyte.String) ([]GeneralName, error) {
	return ParseSANExtension(der)
}

// ParseSDAExtension as described in RFC5280 4.2.1.8
func ParseSDAExtension(der *cryptobyte.String) (string, error) {
	return "SDA", nil
}

// ParseBasicConstraintsExtension as described in RFC5280 4.2.1.9
func ParseBasicConstraintsExtension(der *cryptobyte.String) (string, error) {
	return "BasicConstraints", nil
}

// ParseNameConstraintsExtension as described in RFC5280 4.2.1.10
func ParseNameConstraintsExtension(der *cryptobyte.String) (string, error) {
	return "NameConstraints", nil
}

// ParsePolicyConstraintsExtension as described in RFC5280 4.2.11.11
func ParsePolicyConstraintsExtension(der *cryptobyte.String) (string, error) {
	return "PolicyConstraints", nil
}

// ParseExtKeyUsageExtension as described in RFC5280 4.2.1.12
func ParseExtKeyUsageExtension(der *cryptobyte.String) (string, error) {
	return "ExtKeyUsage", nil
}

// ParseCRLDPExtension as described in RFC5280 4.2.1.13
func ParseCRLDPExtension(der *cryptobyte.String) (string, error) {
	return "CRLDP", nil
}

// ParseInhibitAnyPolicyExtension as described in RFC5280 4.2.1.14
func ParseInhibitAnyPolicyExtension(der *cryptobyte.String) (string, error) {
	return "InhibitAnyPolicy", nil
}

// ParseFreshestCRLExtension as described in RFC5280 4.2.1.15
func ParseFreshestCRLExtension(der *cryptobyte.String) (string, error) {
	return "FreshestCRL", nil
}

//	AccessDescription  ::=  SEQUENCE {
//	  accessMethod   OBJECT IDENTIFIER,
//	  accessLocation GeneralName  }
type AccessDescription struct {
	AccessMethod   ObjectIdentifier
	AccessLocation GeneralName
}

// ParseAIAExtension as described in RFC5280 4.2.2.1
func ParseAIAExtension(der *cryptobyte.String) ([]AccessDescription, error) {
	var aia cryptobyte.String
	if !der.ReadASN1(&aia, asn1.SEQUENCE) {
		return nil, errors.New("failed to read AIA Extension")
	}

	var accessDescriptions []AccessDescription

	// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
	for !aia.Empty() {
		var accessDescription cryptobyte.String
		if !aia.ReadASN1(&accessDescription, asn1.SEQUENCE) {
			return nil, errors.New("failed to read AIA Extension")
		}
		oid, err := ParseObjectIdentifier(&accessDescription)
		if err != nil {
			return nil, fmt.Errorf("parsing AccessMethod: %w", err)
		}

		accessLocation, err := ParseGeneralName(&accessDescription)
		if err != nil {
			return nil, fmt.Errorf("parsing AccessLocation: %w", err)
		}

		accessDescriptions = append(accessDescriptions, AccessDescription{
			AccessMethod:   oid,
			AccessLocation: accessLocation,
		})
	}

	return accessDescriptions, nil
}

// ParseSIAExtension as described in RFC5280 4.2.2.2
func ParseSIAExtension(der *cryptobyte.String) ([]AccessDescription, error) {
	// Same as AIA:
	return ParseAIAExtension(der)
}

// ParseSCTExtension as described in RFC6962 3.3
func ParseSCTExtension(der *cryptobyte.String) (SCTExtension, error) {
	var extension cryptobyte.String
	if !der.ReadASN1(&extension, asn1.OCTET_STRING) {
		return SCTExtension{}, errors.New("failed to read SCT extension")
	}

	// The contents of the OCTET_STRING are a TLS structure:
	//
	// opaque SerializedSCT<1..2^16-1>;
	//
	// struct {
	//   SerializedSCT sct_list <1..2^16-1>;
	// } SignedCertificateTimestampList;

	return SCTExtension{
		Raw: extension,
	}, nil
}

type PrecertificatePoisonExtension struct{}

// ParsePrecertificatePoisonExtension as described in RFC6962 3.1
func ParsePrecertificatePoisonExtension(der *cryptobyte.String) (PrecertificatePoisonExtension, error) {
	if !der.ReadASN1(nil, asn1.NULL) {
		return PrecertificatePoisonExtension{}, errors.New("failed to read precertificate poison extension")
	}

	return PrecertificatePoisonExtension{}, nil
}

// ParseTLSFeatureExtension as described in RFC7633
// This is used for OCSP must-staple, though theoretically could be used for other reasons.
func ParseTLSFeatureExtension(der *cryptobyte.String) ([]uint16, error) {
	// The ASN.1 module in RFC 7633 is just
	//    Features ::= SEQUENCE OF INTEGER
	// On the TLS side, though, they're defined as being 16-bit, so we use a uint16 here.

	var featureSequence cryptobyte.String
	if !der.ReadASN1(&featureSequence, asn1.SEQUENCE) {
		return nil, errors.New("failed to read TLS feature extension")
	}

	var features []uint16

	for !featureSequence.Empty() {
		var feature uint16
		if !featureSequence.ReadASN1Integer(&feature) {
			return nil, errors.New("failed to read TLS Feature Extension")
		}
		features = append(features, feature)
	}
	return features, nil
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

// ParseGeneralName parses a GeneralName as defined in RFC5280 4.2.1.6
// Tag is the context-sensitive tag from the GeneralName CHOICE, and the constants above.
// TODO: Is a string the best way to represent these names?
func ParseGeneralName(der *cryptobyte.String) (GeneralName, error) {
	var data cryptobyte.String
	var tag asn1.Tag
	if !der.ReadAnyASN1(&data, &tag) {
		return GeneralName{}, errors.New("failed to read general name")
	}

	// remove context-specific bit
	tag = tag ^ 0x80

	var value string

	switch tag {
	case RFC822Name, DNSName, UniformResourceIdentifier:
		// IA5String
		value = string(data)
	case IPAddress:
		// Octet String
		value = net.IP(data).String()
	default:
		// TODO: Unsupported are just hex encoded
		value = hex.EncodeToString(data)
	}

	return GeneralName{
		Tag:   tag,
		Value: value,
	}, nil
}
