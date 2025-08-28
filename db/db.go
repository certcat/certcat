// Package db handles inserting and querying the certcat Clickhouse
package db

import (
	"context"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type Handle struct {
	conn driver.Conn
}

func New(conn driver.Conn) (*Handle, error) {
	return &Handle{conn: conn}, nil
}

func (h *Handle) Close() error {
	return h.conn.Close()
}

// InsertCertificates in a batch
func (h *Handle) InsertCertificates(ctx context.Context, certs []Certificate) error {
	batch, err := h.conn.PrepareBatch(ctx, "INSERT INTO certcat.certs")
	if err != nil {
		return err
	}
	defer batch.Close()

	for _, cert := range certs {
		err := batch.Append(
			cert.SHA256,
			cert.Serial,
			cert.SignatureAlgorithmOID,
			cert.Issuer,
			cert.NotBefore,
			cert.NotAfter,
			cert.Subject,
			cert.SPKIAlgorithmOID,
			cert.SPKISHA256,
			cert.Extensions,
			cert.SCTs,
			cert.PreCertificatePoison,
			cert.AIAOCSP,
			cert.AIACAIssuers,
			cert.CRLDPs,
			cert.OCSPMustStaple,
			cert.SKID,
			cert.AKID,
			cert.KeyUsages,
			cert.EKUs,
			cert.BasicConstraintsIsCA,
			cert.BasicConstraintsPathLen,
			cert.DNSSANs,
			cert.IPv4SANs,
			cert.IPv6SANs,
			cert.Raw,
		)
		if err != nil {
			return err
		}
	}

	return batch.Send()
}
