package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Test helpers: a private certificate authority, leaf certificates with
// chosen dates and names, and in-process TLS servers. Nothing here touches
// the internet.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial struct {
	sync.Mutex
	n int64
}

func nextSerial() *big.Int {
	serial.Lock()
	defer serial.Unlock()
	serial.n++
	return big.NewInt(serial.n)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, tmpl, parent *x509.Certificate, pub any, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// newRootCA makes a self-signed root.
func newRootCA(t *testing.T, name string) *testCA {
	key := newKey(t)
	tmpl := caTemplate(name)
	return &testCA{cert: sign(t, tmpl, tmpl, &key.PublicKey, key), key: key}
}

// newIntermediate makes a CA signed by parent.
func newIntermediate(t *testing.T, parent *testCA, name string) *testCA {
	key := newKey(t)
	return &testCA{cert: sign(t, caTemplate(name), parent.cert, &key.PublicKey, parent.key), key: key}
}

type leafSpec struct {
	names     []string
	notBefore time.Time
	notAfter  time.Time
	issuerURL string // Authority Information Access link to the issuer
}

// newLeaf makes a server certificate. With issuer nil it is self-signed.
func newLeaf(t *testing.T, issuer *testCA, spec leafSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: spec.names[0]},
		DNSNames:     spec.names,
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if spec.issuerURL != "" {
		tmpl.IssuingCertificateURL = []string{spec.issuerURL}
	}
	if issuer == nil {
		return sign(t, tmpl, tmpl, &key.PublicKey, key), key
	}
	return sign(t, tmpl, issuer.cert, &key.PublicKey, issuer.key), key
}

// chainFor builds what the server sends: the leaf, then any intermediates.
func chainFor(leaf *x509.Certificate, key *ecdsa.PrivateKey, intermediates ...*x509.Certificate) tls.Certificate {
	c := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	for _, ic := range intermediates {
		c.Certificate = append(c.Certificate, ic.Raw)
	}
	return c
}

// startTLS serves cert with httptest and returns the listening address.
func startTLS(t *testing.T, cert tls.Certificate, tune func(*tls.Config)) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "hello")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the probes cause expected handshake errors
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if tune != nil {
		tune(srv.TLS)
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// fakeNet maps "name:443" to the address of a local test server, like a
// tiny private DNS. Addresses it does not know are dialled as they are.
// The map is filled before any check starts and only read afterwards.
type fakeNet map[string]string

func (n fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if real, ok := n[addr]; ok {
		addr = real
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func days(n float64) time.Duration { return time.Duration(n * 24 * float64(time.Hour)) }
