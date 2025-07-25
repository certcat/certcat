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
	if atv.Tag == asn1.PrintableString || atv.Tag == asn1.UTF8String || atv.Tag == asn1.IA5String {
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
		return Extension{}, fmt.Errorf("parsing extension %s value: %w", extnID, err)
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
	case "1.3.6.1.5.5.7.1.24":
		ret, err = ParseTLSFeatureExtension(&val)
	case "2.5.29.14":
		ret, err = ParseSKIExtension(&val)
	case "2.5.29.15":
		ret, err = ParseKeyUsageExtension(&val)
	case "2.5.29.17":
		ret, err = ParseSANExtension(&val)
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
	case "2.5.29.37":
		ret, err = ParseExtKeyUsageExtension(&val)
	case "2.5.29.54":
		ret, err = ParseInhibitAnyPolicyExtension(&val)
	case "1.2.840.113533.7.65.0": // 1
		ret, err = ParseEntrustVersionExtension(&val)
	case "2.5.29.16": // 1
		ret, err = ParsePrivateKeyUsagePeriodExtension(&val)
	default:
		ret = UnknownExtension{
			Unknown: val,
		}
		val.Skip(len(val))
	}

	if !val.Empty() {
		return nil, fmt.Errorf("data after extension %s: %s", oid.String(), hex.EncodeToString(val))
	}

	return ret, err
}

type UnknownExtension struct {
	Unknown []byte
}

type SCTExtension struct {
	Raw []byte
}

type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte
	AuthorityCertIssuer       []GeneralName           `json:",omitempty"`
	AuthorityCertSerialNumber CertificateSerialNumber `json:",omitempty"`
}

// ParseAKIExtension as described in RFC5280 4.2.1.1
func ParseAKIExtension(der *cryptobyte.String) (AuthorityKeyIdentifier, error) {
	//    AuthorityKeyIdentifier ::= SEQUENCE {
	//      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	//      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	//      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
	//    KeyIdentifier ::= OCTET STRING
	var aki cryptobyte.String
	if !der.ReadASN1(&aki, asn1.SEQUENCE) {
		return AuthorityKeyIdentifier{}, errors.New("failed to read AKI extension")
	}

	var keyID cryptobyte.String
	var hasKeyID bool
	if !aki.ReadOptionalASN1(&keyID, &hasKeyID, asn1.Tag(0).ContextSpecific()) {
		return AuthorityKeyIdentifier{}, errors.New("failed to read AKI extension")
	}

	var certIssuer cryptobyte.String
	var hasCertIssuer bool
	if !aki.ReadOptionalASN1(&certIssuer, &hasCertIssuer, asn1.Tag(1).Constructed().ContextSpecific()) {
		return AuthorityKeyIdentifier{}, errors.New("failed to read AKI extension: AuthorityCertIssuer")
	}

	var authorityCertIssuer []GeneralName
	if hasCertIssuer {
		for !certIssuer.Empty() {
			name, err := ParseGeneralName(&certIssuer, false)
			if err != nil {
				return AuthorityKeyIdentifier{}, fmt.Errorf("parsing Issuer name: %w", err)
			}
			authorityCertIssuer = append(authorityCertIssuer, name)
		}
	}

	var serial cryptobyte.String
	var hasSerial bool
	if !aki.ReadOptionalASN1(&serial, &hasSerial, asn1.Tag(2).ContextSpecific()) {
		return AuthorityKeyIdentifier{}, errors.New("failed to read AKI extension: SerialNumber")
	}

	if !aki.Empty() {
		return AuthorityKeyIdentifier{}, errors.New("trailing data after AKI extension")
	}

	return AuthorityKeyIdentifier{
		KeyIdentifier:             keyID,
		AuthorityCertIssuer:       authorityCertIssuer,
		AuthorityCertSerialNumber: CertificateSerialNumber(serial),
	}, nil
}

// ParseSKIExtension as described in RFC5280 4.2.1.2
func ParseSKIExtension(der *cryptobyte.String) ([]byte, error) {
	//    SubjectKeyIdentifier ::= KeyIdentifier
	var keyID cryptobyte.String
	if !der.ReadASN1(&keyID, asn1.OCTET_STRING) {
		return nil, errors.New("failed to read Key ID")
	}

	return keyID, nil
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

type PrivateKeyUsagePeriod struct {
	NotBefore *time.Time `json:",omitempty"`
	NotAfter  *time.Time `json:",omitempty"`
}

const generalizedTimeFormatStr = "20060102150405Z0700"

// ParsePrivateKeyUsagePeriodExtension as described in RFC3280 (note: Not 5280)
func ParsePrivateKeyUsagePeriodExtension(der *cryptobyte.String) (PrivateKeyUsagePeriod, error) {
	// PrivateKeyUsagePeriod ::= SEQUENCE {
	//     notBefore       [0]     GeneralizedTime OPTIONAL,
	//     notAfter        [1]     GeneralizedTime OPTIONAL }

	var kup cryptobyte.String
	if !der.ReadASN1(&kup, asn1.SEQUENCE) {
		return PrivateKeyUsagePeriod{}, errors.New("failed to read PrivateKeyUsagePeriod extension")
	}

	var notBefore cryptobyte.String
	var hasNotBefore bool
	if !kup.ReadOptionalASN1(&notBefore, &hasNotBefore, asn1.Tag(0).ContextSpecific()) {
		return PrivateKeyUsagePeriod{}, errors.New("failed to read PrivateKeyUsagePeriod extension notBefore")
	}

	var ret PrivateKeyUsagePeriod

	if hasNotBefore {
		nb, err := time.Parse(generalizedTimeFormatStr, string(notBefore))
		if err != nil {
			return PrivateKeyUsagePeriod{}, fmt.Errorf("parsing notBefore: %w", err)
		}
		ret.NotBefore = &nb
	}

	var notAfter cryptobyte.String
	var hasNotAfter bool
	if !kup.ReadOptionalASN1(&notAfter, &hasNotAfter, asn1.Tag(1).ContextSpecific()) {
		return PrivateKeyUsagePeriod{}, errors.New("failed to read PrivateKeyUsagePeriod extension notAfter")
	}

	if hasNotAfter {
		na, err := time.Parse(generalizedTimeFormatStr, string(notAfter))
		if err != nil {
			return PrivateKeyUsagePeriod{}, fmt.Errorf("parsing notAfter: %w", err)
		}
		ret.NotAfter = &na
	}

	return ret, nil
}

type PolicyInformation struct {
	PolicyIdentifier ObjectIdentifier
	PolicyQualifiers []PolicyQualifierInfo `json:",omitempty"`
}

type PolicyQualifierInfo struct {
	PolicyQualifierID ObjectIdentifier
	Qualifier         string // TODO: structured representation
}

// ParseCertPoliciesExtension as described in RFC5280 4.2.1.4
func ParseCertPoliciesExtension(der *cryptobyte.String) ([]PolicyInformation, error) {
	var certPolicies cryptobyte.String
	if !der.ReadASN1(&certPolicies, asn1.SEQUENCE) {
		return nil, errors.New("failed to read certificate policies")
	}

	var policies []PolicyInformation

	for !certPolicies.Empty() {
		var certPolicy cryptobyte.String
		if !certPolicies.ReadASN1(&certPolicy, asn1.SEQUENCE) {
			return nil, errors.New("failed to read certificate policy")
		}

		oid, err := ParseObjectIdentifier(&certPolicy)
		if err != nil {
			return nil, err
		}

		var policyQualifiers []PolicyQualifierInfo
		if !certPolicy.Empty() {
			var qualifiers cryptobyte.String
			if !certPolicy.ReadASN1(&qualifiers, asn1.SEQUENCE) {
				return nil, errors.New("failed to read certificate qualifiers sequence")
			}

			for !qualifiers.Empty() {
				q, err := ParseCertPolicyQualifierInfo(&qualifiers)
				if err != nil {
					return nil, err
				}
				policyQualifiers = append(policyQualifiers, q)
			}
		}

		policies = append(policies, PolicyInformation{
			PolicyIdentifier: oid,
			PolicyQualifiers: policyQualifiers,
		})

	}
	return policies, nil
}

func ParseCertPolicyQualifierInfo(der *cryptobyte.String) (PolicyQualifierInfo, error) {
	var qualifier cryptobyte.String
	if !der.ReadASN1(&qualifier, asn1.SEQUENCE) {
		return PolicyQualifierInfo{}, errors.New("failed to read certificate qualifier sequence")
	}

	qoid, err := ParseObjectIdentifier(&qualifier)
	if err != nil {
		return PolicyQualifierInfo{}, err
	}

	var qval string

	switch qoid.String() {
	case "1.3.6.1.5.5.7.2.1": // id-qt-cps
		var cpsURI cryptobyte.String
		if !qualifier.ReadASN1(&cpsURI, asn1.IA5String) {
			return PolicyQualifierInfo{}, errors.New("failed to read certificate qualifier URI")
		}
		qval = string(cpsURI)
	case "1.3.6.1.5.5.7.2.2": // id-qt-unotice
		var userNotice cryptobyte.String
		if !qualifier.ReadASN1(&userNotice, asn1.SEQUENCE) {
			return PolicyQualifierInfo{}, errors.New("failed to read User Notice")
		}

		var tag asn1.Tag
		var data cryptobyte.String

		if !userNotice.ReadAnyASN1(&data, &tag) {
			return PolicyQualifierInfo{}, errors.New("failed to read certificate qualifier tag")
		}

		switch tag {
		case asn1.SEQUENCE:
			// TODO: NoticeReference
			qval = "NoticeReference:" + hex.EncodeToString(data)
		case asn1.IA5String, asn1.UTF8String, encoding_asn1.TagBMPString:
			qval, err = parseString(tag, data)
			if err != nil {
				return PolicyQualifierInfo{}, err
			}
		}
	default:
		// Other qualifiers are unsupported
		qval = hex.EncodeToString(qualifier)
	}

	return PolicyQualifierInfo{
		PolicyQualifierID: qoid,
		Qualifier:         qval,
	}, nil
}

type PolicyMap struct {
	IssuerDomainPolicy  ObjectIdentifier
	SubjectDomainPolicy ObjectIdentifier
}

// ParsePolicyMappingsExtension as described in RFC5280 4.2.1.5
func ParsePolicyMappingsExtension(der *cryptobyte.String) ([]PolicyMap, error) {
	var policyMaps cryptobyte.String
	if !der.ReadASN1(&policyMaps, asn1.SEQUENCE) {
		return nil, errors.New("failed to read policy mappings")
	}

	var ret []PolicyMap

	for !policyMaps.Empty() {
		var policyMap cryptobyte.String
		if !policyMaps.ReadASN1(&policyMap, asn1.SEQUENCE) {
			return nil, errors.New("failed to read policy mapping")
		}
		issuerOID, err := ParseObjectIdentifier(&policyMap)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer OID: %w", err)
		}
		subjectOID, err := ParseObjectIdentifier(&policyMap)
		if err != nil {
			return nil, fmt.Errorf("failed to parse subject OID: %w", err)
		}

		ret = append(ret, PolicyMap{
			IssuerDomainPolicy:  issuerOID,
			SubjectDomainPolicy: subjectOID,
		})
	}

	return ret, nil
}

// ParseSANExtension as described in RFC5280 4.2.1.6
func ParseSANExtension(der *cryptobyte.String) ([]GeneralName, error) {
	var sans cryptobyte.String
	if !der.ReadASN1(&sans, asn1.SEQUENCE) {
		return nil, errors.New("failed to parse SAN extension")
	}

	var ret []GeneralName

	for !sans.Empty() {
		name, err := ParseGeneralName(&sans, false)
		if err != nil {
			return nil, fmt.Errorf("parsing SAN: %w", err)
		}

		ret = append(ret, name)
	}

	return ret, nil
}

type BasicConstraints struct {
	CA                   bool
	PathLengthConstraint *int `json:",omitempty"`
}

// ParseBasicConstraintsExtension as described in RFC5280 4.2.1.9
//
//	BasicConstraints ::= SEQUENCE {
//	    cA                      BOOLEAN DEFAULT FALSE,
//	    pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
func ParseBasicConstraintsExtension(der *cryptobyte.String) (BasicConstraints, error) {
	var bce cryptobyte.String
	if !der.ReadASN1(&bce, asn1.SEQUENCE) {
		return BasicConstraints{}, errors.New("failed to parse basic constraints")
	}

	var CA bool
	if bce.PeekASN1Tag(asn1.BOOLEAN) {
		if !bce.ReadASN1Boolean(&CA) {
			return BasicConstraints{}, errors.New("failed to parse basic constraints CA")
		}
	}

	if bce.PeekASN1Tag(asn1.INTEGER) {
		pathLen := -1
		if !bce.ReadASN1Integer(&pathLen) {
			return BasicConstraints{}, errors.New("failed to parse basic constraints path length")
		}
		return BasicConstraints{
			CA:                   CA,
			PathLengthConstraint: &pathLen,
		}, nil
	}

	return BasicConstraints{
		CA:                   CA,
		PathLengthConstraint: nil,
	}, nil
}

type NameConstraints struct {
	PermittedSubtrees []GeneralName `json:",omitempty"`
	ExcludedSubtrees  []GeneralName `json:",omitempty"`
}

func ParseGeneralSubtrees(der *cryptobyte.String) ([]GeneralName, error) {
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	// GeneralSubtree ::= SEQUENCE {
	//     base                    GeneralName,
	//     minimum         [0]     BaseDistance DEFAULT 0,
	//     maximum         [1]     BaseDistance OPTIONAL }
	//
	//  BaseDistance ::= INTEGER (0..MAX)
	// Because RFC5280 says minimum and maximum can't be present, we don't support them.
	var ret []GeneralName

	for !der.Empty() {
		var subtree cryptobyte.String
		if !der.ReadASN1(&subtree, asn1.SEQUENCE) {
			return nil, errors.New("failed to parse general subtrees")
		}

		name, err := ParseGeneralName(&subtree, true)
		if err != nil {
			return nil, err
		}
		ret = append(ret, name)
	}

	return ret, nil
}

// ParseNameConstraintsExtension as described in RFC5280 4.2.1.10
func ParseNameConstraintsExtension(der *cryptobyte.String) (NameConstraints, error) {
	// NameConstraints ::= SEQUENCE {
	//     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	var nc cryptobyte.String
	if !der.ReadASN1(&nc, asn1.SEQUENCE) {
		return NameConstraints{}, errors.New("failed to parse name constraints extension")
	}

	var permitted cryptobyte.String
	var hasPermitted bool
	if !nc.ReadOptionalASN1(&permitted, &hasPermitted, asn1.Tag(0).Constructed().ContextSpecific()) {
		return NameConstraints{}, errors.New("failed to parse name constraints extension: permitted subtrees")
	}

	permittedSubtrees, err := ParseGeneralSubtrees(&permitted)
	if err != nil {
		return NameConstraints{}, err
	}

	var excluded cryptobyte.String
	var hasExcludedSubtrees bool
	if !nc.ReadOptionalASN1(&excluded, &hasExcludedSubtrees, asn1.Tag(1).Constructed().ContextSpecific()) {
		return NameConstraints{}, errors.New("failed to parse name constraints extension: excluded subtrees")
	}

	excludedSubtrees, err := ParseGeneralSubtrees(&excluded)
	if err != nil {
		return NameConstraints{}, err
	}

	return NameConstraints{
		PermittedSubtrees: permittedSubtrees,
		ExcludedSubtrees:  excludedSubtrees,
	}, nil
}

// ParseExtKeyUsageExtension as described in RFC5280 4.2.1.12
func ParseExtKeyUsageExtension(der *cryptobyte.String) ([]ObjectIdentifier, error) {
	//  KeyPurposeId ::= OBJECT IDENTIFIER
	//  ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

	var ekus cryptobyte.String
	if !der.ReadASN1(&ekus, asn1.SEQUENCE) {
		return nil, errors.New("failed to parse key usage extension")
	}

	var ret []ObjectIdentifier

	for !ekus.Empty() {
		ident, err := ParseObjectIdentifier(&ekus)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ident)
	}

	return ret, nil
}

type DistributionPoint struct {
	// The DPN could theoretically be a RelativeDistinguishedName
	// However, that's not permitted in BRs, and is unused.
	DistributionPointName GeneralName
}

// ParseCRLDPExtension as described in RFC5280 4.2.1.13
// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//
//	DistributionPoint ::= SEQUENCE {
//	     distributionPoint       [0]     DistributionPointName OPTIONAL,
//	     reasons                 [1]     ReasonFlags OPTIONAL,
//	     cRLIssuer               [2]     GeneralNames OPTIONAL }
//
//	DistributionPointName ::= CHOICE {
//	     fullName                [0]     GeneralNames,
//	     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
//
// ReasonFlags ::= BIT STRING
func ParseCRLDPExtension(der *cryptobyte.String) ([]DistributionPoint, error) {
	var dps cryptobyte.String
	if !der.ReadASN1(&dps, asn1.SEQUENCE) {
		return nil, errors.New("failed to read CRL Distribution Points extension")
	}

	var ret []DistributionPoint

	for !dps.Empty() {
		var dp cryptobyte.String
		if !dps.ReadASN1(&dp, asn1.SEQUENCE) {
			return nil, errors.New("failed to read CRL Distribution Point")
		}

		var dpn cryptobyte.String
		var hasDPN bool
		if !dp.ReadOptionalASN1(&dpn, &hasDPN, asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("failed to read CRL Distribution Point Name")
		}
		if !hasDPN {
			return nil, fmt.Errorf("DistributionPoint had no Distribution Point Name in %s", hex.EncodeToString(dp))
		}

		var fullName cryptobyte.String
		var hasFullName bool
		if !dpn.ReadOptionalASN1(&fullName, &hasFullName, asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("failed to read FullName")
		}

		gn, err := ParseGeneralName(&fullName, false)
		if err != nil {
			return nil, err
		}

		if !dp.Empty() {
			// reasons and CRLIssuer are "MUST NOT" per CA/B BRs, so assume they don't occur
			return nil, errors.New("unsupported CRLDP options")
		}

		ret = append(ret, DistributionPoint{DistributionPointName: gn})
	}

	return ret, nil
}

// ParseInhibitAnyPolicyExtension as described in RFC5280 4.2.1.14
func ParseInhibitAnyPolicyExtension(der *cryptobyte.String) (uint, error) {
	var skipCerts uint
	if !der.ReadASN1Integer(&skipCerts) {
		return 0, errors.New("failed to parse inhibit any policy extension")
	}
	return skipCerts, nil
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

		accessLocation, err := ParseGeneralName(&accessDescription, false)
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

// ParseSCTExtension as described in RFC6962 3.3
func ParseSCTExtension(der *cryptobyte.String) (SCTExtension, error) {
	var extension cryptobyte.String
	if !der.ReadASN1(&extension, asn1.OCTET_STRING) {
		return SCTExtension{}, errors.New("failed to read SCT extension")
	}

	// TODO: The contents of the OCTET_STRING are a TLS structure:
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
	var poison cryptobyte.String
	if !der.ReadASN1(&poison, asn1.NULL) {
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

type EntrustVersion struct {
	Version string
	Flags   string
}

// ParseEntrustVersionExtension parses a somewhat-unknown extension
func ParseEntrustVersionExtension(der *cryptobyte.String) (EntrustVersion, error) {
	var entrustVersion cryptobyte.String
	if !der.ReadASN1(&entrustVersion, asn1.SEQUENCE) {
		return EntrustVersion{}, errors.New("failed to read EntrustVersion extension")
	}

	var ver cryptobyte.String
	if !entrustVersion.ReadASN1(&ver, asn1.GeneralString) {
		return EntrustVersion{}, errors.New("failed to read EntrustVersion extension version")
	}

	var flags encoding_asn1.BitString
	if !entrustVersion.ReadASN1BitString(&flags) {
		return EntrustVersion{}, errors.New("failed to read EntrustVersion extension flags")
	}

	var flagString string

	// We don't really know what this field mean, so just turn them into a binary string.
	for i := range flags.BitLength {
		if flags.At(i) != 0 {
			flagString = "1" + flagString
		} else {
			flagString = "0" + flagString
		}
	}

	return EntrustVersion{
		Version: string(ver),
		Flags:   flagString,
	}, nil
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
		rdn, err := ParseRDNSequence(&data)
		if err != nil {
			return GeneralName{}, err
		}
		value = string(rdn)
	default:
		value = hex.EncodeToString(data)
	}

	return GeneralName{
		Tag:   tag,
		Value: value,
	}, nil
}
