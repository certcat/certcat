package x509debug

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

const testCert = `
-----BEGIN CERTIFICATE-----
MIIDrTCCAzKgAwIBAgISBonex7Bbum07r3bZ6A9jE3S1MAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
NjAeFw0yNTAzMTIyMTEzMTdaFw0yNTA2MTAyMTEzMTZaMBkxFzAVBgNVBAMTDnd0
Zi5pbmFoZ2Eub3JnMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfzOrI5rRcDWa
1NEbJROU0l/q9tWo5DiwfGORtZ7ZCgvBcbfNG7JCQhahlZhl32UaHPBI0dclL/ZH
Ej4f500g1qOCAj8wggI7MA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU+9E5v8qxpq/b
YJR31d1DLYaYjqAwHwYDVR0jBBgwFoAUkydGmAOpUWiOmNbEQkjbI79YlNIwVQYI
KwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vZTYuby5sZW5jci5vcmcw
IgYIKwYBBQUHMAKGFmh0dHA6Ly9lNi5pLmxlbmNyLm9yZy8wGQYDVR0RBBIwEIIO
d3RmLmluYWhnYS5vcmcwEwYDVR0gBAwwCjAIBgZngQwBAgEwLQYDVR0fBCYwJDAi
oCCgHoYcaHR0cDovL2U2LmMubGVuY3Iub3JnLzU0LmNybDCCAQQGCisGAQQB1nkC
BAIEgfUEgfIA8AB1AE51oydcmhDDOFts1N8/Uusd8OCOG41pwLH6ZLFimjnfAAAB
lYxp8BoAAAQDAEYwRAIgOcA/kyOuojW1HhlECaiufvXXxt47OePFQZgdzvr89IUC
IF2OEy2zPTs/MFn6KwTUFMV8/3acT6O4Y9+YYJtMGECGAHcAzPsPaoVxCWX+lZtT
zumyfCLphVwNl422qX5UwP5MDbAAAAGVjGn4BwAABAMASDBGAiEAjmkQLrI0q3Y3
3LaO3j7d9YzZnBWCk2AXe1jXRFX4g4wCIQChLwMsIHZaYoYuLj1QlAywdc19VLF7
4LFgtiYBYfxj2DAKBggqhkjOPQQDAwNpADBmAjEA238FAtxb3Tv8R00af4zj4pz5
MlLfnlF6SLNZk3oIOqNGf72Y3AejdLPlHn36JqxYAjEA3HqREtyMfydex8+mEYdy
Fm7j8CrINhKtqeUqnLfNUuFouXiwCCHynlevttKbQvvs
-----END CERTIFICATE-----
`

func TestParseCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(testCert))
	cert := cryptobyte.String(block.Bytes)
	certificate, err := ParseCertificate(&cert)
	if err != nil {
		t.Fatal(err)
	}

	checkTBS(t, certificate.TbsCertificate)

	// unparsed P-384 signature is 104 bytes
	if len(certificate.SignatureValue) != 104 {
		t.Errorf("signature value length %d != 104", len(certificate.SignatureValue))
	}

	data, err := json.MarshalIndent(certificate, "", "  ")
	if err != nil {
		t.Error(fmt.Errorf("json marshal error: %w", err))
	}

	// Later we'll make sure the JSON is right, but just dump for inspection now
	fmt.Printf("%s\n", string(data))
}

func checkTBS(t *testing.T, tbs TBSCertificate) {
	if tbs.Version.String() != "v3(2)" {
		t.Errorf("version mismatch %s != %s", tbs.Version, "v3(2)")
	}

	if tbs.SerialNumber.String() != "0689dec7b05bba6d3baf76d9e80f631374b5" {
		t.Errorf("serial mismatch: %s", tbs.SerialNumber)
	}

	issuerRawHex := hex.EncodeToString(tbs.Issuer.Raw)
	expectedIssuer := "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313024536"
	if issuerRawHex != expectedIssuer {
		t.Errorf("issuer mismatch: %s != %s", issuerRawHex, expectedIssuer)
	}

	if tbs.Validity.NotBefore.Unix() != 1741813997 {
		t.Errorf("validity notBefore mismatch: %d != 1741813997", tbs.Validity.NotBefore.Unix())
	}

	if tbs.Validity.NotAfter.Unix() != 1749589996 {
		t.Errorf("validity NotAfter mismatch: %d != 1749589996", tbs.Validity.NotAfter.Unix())
	}

	subjectRawHex := hex.EncodeToString(tbs.Subject.Raw)
	expectedSubject := "311730150603550403130e7774662e696e616867612e6f7267"
	if subjectRawHex != expectedSubject {
		t.Errorf("subject mismatch: %s != %s", subjectRawHex, expectedSubject)
	}

	// TODO: SPKI
	if tbs.SubjectPublicKeyInfo.Algorithm.Algorithm.String() != "1.2.840.10045.2.1" {
		t.Errorf("unexpected Algorithm OID: %s", tbs.SubjectPublicKeyInfo.Algorithm.Algorithm)
	}

	if tbs.IssuerUniqueID != nil {
		t.Errorf("unexpected IssuerUniqueID: %+v", tbs.IssuerUniqueID)
	}

	if tbs.SubjectUniqueID != nil {
		t.Errorf("unexpected SubjectUniqueID: %+v", tbs.SubjectUniqueID)
	}

	if len(tbs.Extensions) != 10 {
		t.Errorf("extensions length %d != 10", len(tbs.Extensions))
	}
}
