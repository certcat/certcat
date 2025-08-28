CREATE DATABASE IF NOT EXISTS certcat;
CREATE TABLE IF NOT EXISTS certcat.certs
(
    sha256 FixedString(32), -- SHA256 fingerprint of the certificate
    serial String, -- Serial number
    signatureAlgorithmOID LowCardinality(String), -- OID of the signature algorithm
    issuer Array(Tuple(oid LowCardinality(String), value String)), -- Issuer RDNs
    notBefore DateTime('Etc/UTC'),
    notAfter DateTime('Etc/UTC'),
    subject Array(Tuple(oid LowCardinality(String), value String)), -- Subject RDNs
    spkiAlgorithmOID LowCardinality(String), -- OID of the SPKI Algorithm Identifier
    spkiSha256 FixedString(32), -- SHA256 fingerprint of the SPKI

    -- Extensions and the data from them
    extensions Array(Tuple(oid LowCardinality(String), critical Boolean)), -- Extensions in this cert

    scts Array(String), -- TODO represent SCTs
    preCertificatePoison Boolean, -- If the precertificate poison was present
    aiaOcsp Array(String),
    aiaCaIssuers Array(String),
    crldps Array(String),
    ocspMustStaple Boolean,
    skid String, -- Subject Key Identifier
    akid String, -- Authority Key Identifier
    keyUsages Array(UInt8),
    ekus Array(LowCardinality(String)), -- Extended Key Usage OIDs
    basicConstraintsIsCA Nullable(Boolean),
    basicConstraintsPathLen Nullable(UInt32),

    -- TODO: More extensions, like Name constraints, Policies, PolicyMapping, inhibitAnyPolicy

    -- SANS, by type:
    dnsSans Array(String),
    ipv4Sans Array(IPv4),
    ipv6Sans Array(IPv6)
    -- TODO, other SANs
)
Engine = ReplacingMergeTree()
ORDER BY (notAfter, serial, preCertificatePoison, sha256)
PARTITION BY toYYYYMM(notAfter)
SETTINGS index_granularity = 8192;

-- TODO: Projections and/or Materialized Views
-- * Projections for faster lookups
--   * with _part_offset for fingerprint, spki, serial lookups
--   * some sort of SAN index
--   * some sort of subject index on O/OU for EV/OV
-- * Materialized Views with aggregate statistics
--   * Counts of certificates by varying parameters for dashboarding

-- TODO: Future Tables:
-- * CT log map
--   * Track what's been read from CT logs, and generate statistics
--   * (timestamp, log id, index, leaf hash, cert fingerprint, chain)
-- * CRLs:
--   * What CRLs were observed. One row per CRL.
--   * (thisUpdate, nextUpdate, issuer, number, fingerprint)
-- * Revocations:
--   * The contents of CRLs. What certs are revoked
--   * issuer, number, serial
-- * Trust stores / Data from CCADB
--    * What roots are trusted
