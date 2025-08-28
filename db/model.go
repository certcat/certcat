package db

import (
	"net"
	"time"

	"github.com/certcat/certcat/x509debug"
)

// Certificate is the higher-level, flat representation of a certificate, as stored in the Certcat.dev database.
type Certificate struct {
	SHA256                [32]byte
	Serial                []byte
	SignatureAlgorithmOID string
	Issuer                []map[string]string
	NotBefore             time.Time
	NotAfter              time.Time
	Subject               []map[string]string
	SPKIAlgorithmOID      string
	SPKISHA256            [32]byte

	Extensions []map[string]any

	SCTs                    [][]byte
	PreCertificatePoison    bool
	AIACAIssuers            []string
	AIAOCSP                 []string
	CRLDPs                  []string
	OCSPMustStaple          bool
	SKID                    []byte
	AKID                    []byte
	KeyUsages               []uint8
	EKUs                    []string
	BasicConstraintsIsCA    *bool
	BasicConstraintsPathLen *uint32

	DNSSANs  []string
	IPv4SANs []net.IP
	IPv6SANs []net.IP

	Raw []byte
}

// ConvertRDNs to the DB format
func ConvertRDNs(rdns x509debug.RDNSequence) []map[string]string {
	var ret []map[string]string

	for _, rdn := range rdns {
		for _, atv := range rdn {
			ret = append(ret, map[string]string{"oid": atv.Type.String(), "value": string(atv.Value)})
		}
	}

	return ret
}

// ConvertCertificate a certificate from the parser form to the DB Model
func ConvertCertificate(certificate *x509debug.Certificate) (Certificate, error) {
	ret := Certificate{
		SHA256:                certificate.SHA256,
		Serial:                certificate.TbsCertificate.SerialNumber,
		SignatureAlgorithmOID: certificate.TbsCertificate.Signature.Algorithm.String(), // TODO: Signature Algorithm Parameters
		Issuer:                ConvertRDNs(certificate.TbsCertificate.Issuer),
		NotBefore:             certificate.TbsCertificate.Validity.NotBefore.Time,
		NotAfter:              certificate.TbsCertificate.Validity.NotAfter.Time,
		Subject:               ConvertRDNs(certificate.TbsCertificate.Subject),
		SPKIAlgorithmOID:      certificate.TbsCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm.String(), // TODO: SPKI Algorithm Parameters

		SPKISHA256: [32]byte{}, // TODO: Calculate SPKI Hash
	}

	var extensions []map[string]any

	for _, ext := range certificate.TbsCertificate.Extensions {
		oid := ext.ExtnId.String()
		extensions = append(extensions, map[string]any{"oid": oid, "critical": ext.Critical})

		switch oid {
		case "1.3.6.1.4.1.11129.2.4.2":
			// TODO SCTs
		case "1.3.6.1.4.1.11129.2.4.3":
			ret.PreCertificatePoison = true
		case "1.3.6.1.5.5.7.1.1":
			for _, aia := range ext.ExtnValue.([]x509debug.AccessDescription) {
				switch aia.AccessMethod.String() {
				case "1.3.6.1.5.5.7.48.1":
					ret.AIAOCSP = append(ret.AIAOCSP, aia.AccessLocation.Value)
				case "1.3.6.1.5.5.7.48.2":
					ret.AIACAIssuers = append(ret.AIACAIssuers, aia.AccessLocation.Value)
				}
			}
		case "1.3.6.1.5.5.7.1.24":
			for _, feature := range ext.ExtnValue.([]x509debug.TLSFeature) {
				if feature == 5 {
					ret.OCSPMustStaple = true
				}
			}
		case "2.5.29.14":
			ret.SKID = ext.ExtnValue.([]byte)
		case "2.5.29.15":
			for _, ku := range ext.ExtnValue.([]x509debug.KeyUsage) {
				ret.KeyUsages = append(ret.KeyUsages, uint8(ku))
			}
		case "2.5.29.17":
			for _, san := range ext.ExtnValue.([]x509debug.GeneralName) {
				switch san.Tag {
				case x509debug.DNSName:
					ret.DNSSANs = append(ret.DNSSANs, san.Value)
				case x509debug.IPAddress:
					// TODO: Needing to re-parse here is annoying
					// TODO: Consider changing GeneralName to store an IP
					ip := net.ParseIP(san.Value)
					if ip.To4() == nil {
						ret.IPv6SANs = append(ret.IPv6SANs, ip)
					} else {
						ret.IPv4SANs = append(ret.IPv4SANs, ip.To4())
					}
				}
			}
		case "2.5.29.19":
			bc := ext.ExtnValue.(x509debug.BasicConstraints)
			ret.BasicConstraintsIsCA = &bc.CA
			ret.BasicConstraintsPathLen = bc.PathLengthConstraint
		case "2.5.29.31":
			for _, crldp := range ext.ExtnValue.([]x509debug.DistributionPoint) {
				ret.CRLDPs = append(ret.CRLDPs, crldp.DistributionPointName.Value)
			}
		case "2.5.29.35":
			ret.AKID = ext.ExtnValue.(x509debug.AuthorityKeyIdentifier).KeyIdentifier
		case "2.5.29.37":
			for _, eku := range ext.ExtnValue.([]x509debug.ObjectIdentifier) {
				ret.EKUs = append(ret.EKUs, eku.String())
			}
		}
	}
	ret.Extensions = extensions

	return ret, nil
}
