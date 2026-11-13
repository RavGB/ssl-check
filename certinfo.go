package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// CertInfo describes the certificate a server presented.
type CertInfo struct {
	SubjectCN          string    `json:"subject_cn"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"valid_from"`
	NotAfter           time.Time `json:"valid_to"`
	DaysLeft           int       `json:"days_left"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	NameMatches        bool      `json:"name_matches"`
	Trusted            bool      `json:"trusted"`
	UntrustedReasons   []string  `json:"untrusted_reasons,omitempty"`
	KeyType            string    `json:"key_type"`
	KeyBits            int       `json:"key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	ChainSent          int       `json:"certificates_sent"`
}

func describeCert(leaf *x509.Certificate, now time.Time) CertInfo {
	info := CertInfo{
		SubjectCN:          leaf.Subject.CommonName,
		Issuer:             issuerName(leaf),
		NotBefore:          leaf.NotBefore.UTC(),
		NotAfter:           leaf.NotAfter.UTC(),
		DaysLeft:           wholeDays(leaf.NotAfter.Sub(now)),
		DNSNames:           append([]string{}, leaf.DNSNames...),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
	}
	for _, ip := range leaf.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	info.KeyType, info.KeyBits = keyInfo(leaf.PublicKey)
	return info
}

// wholeDays counts complete days, rounding toward zero: 10 days and 5 hours
// is 10, and 2 days and 5 hours in the past is -2.
func wholeDays(d time.Duration) int {
	return int(d / (24 * time.Hour))
}

func issuerName(c *x509.Certificate) string {
	cn := c.Issuer.CommonName
	org := ""
	if len(c.Issuer.Organization) > 0 {
		org = c.Issuer.Organization[0]
	}
	switch {
	case cn != "" && org != "" && org != cn:
		return cn + ", " + org
	case cn != "":
		return cn
	case org != "":
		return org
	default:
		return "(not named)"
	}
}

func keyInfo(pub any) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return fmt.Sprintf("%T", pub), 0
	}
}
