// internal/freeipa/client_test.go
package freeipa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/freeipa"
)

// stubIPA returns an httptest.Server that mimics FreeIPA's login + JSON RPC endpoints.
func stubIPA(t *testing.T) (*httptest.Server, *x509.Certificate, []byte) {
	t.Helper()

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	mux := http.NewServeMux()

	mux.HandleFunc("/ipa/session/login_password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: "stub-session"})
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/ipa/json", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method := req["method"].(string)

		switch method {
		case "ca_show":
			resp := map[string]interface{}{
				"id": 0,
				"result": map[string]interface{}{
					"result": map[string]interface{}{
						"certificate": base64.StdEncoding.EncodeToString(caDER),
					},
				},
				"error": nil,
			}
			json.NewEncoder(w).Encode(resp)

		case "cert_request":
			leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "testuser"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
			}
			leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
			resp := map[string]interface{}{
				"id": 0,
				"result": map[string]interface{}{
					"result": map[string]interface{}{
						"certificate": base64.StdEncoding.EncodeToString(leafDER),
					},
				},
				"error": nil,
			}
			json.NewEncoder(w).Encode(resp)
		}
	})

	srv := httptest.NewTLSServer(mux)
	return srv, caCert, caDER
}

func TestClient_ReauthOn401(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	var rpcCallCount atomic.Int32
	mux := http.NewServeMux()

	mux.HandleFunc("/ipa/session/login_password", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: "stub-session"})
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/ipa/json", func(w http.ResponseWriter, r *http.Request) {
		n := rpcCallCount.Add(1)
		if n == 1 {
			// First call simulates an expired session; triggers re-auth in rpc().
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := map[string]interface{}{
			"id": 0,
			"result": map[string]interface{}{
				"result": map[string]interface{}{
					"certificate": base64.StdEncoding.EncodeToString(caDER),
				},
			},
			"error": nil,
		}
		json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	client := freeipa.NewWithHTTPClient(host, "pint", "secret", srv.Client())
	if err := client.Login(); err != nil {
		t.Fatal(err)
	}

	gotDER, err := client.CAShow("ipa")
	if err != nil {
		t.Fatalf("CAShow() after 401 re-auth: %v", err)
	}
	if string(gotDER) != string(caDER) {
		t.Error("CAShow returned unexpected DER bytes after re-auth")
	}
	if n := rpcCallCount.Load(); n != 2 {
		t.Errorf("expected 2 RPC calls (401 + retry), got %d", n)
	}
}

func TestClient_Login(t *testing.T) {
	srv, _, _ := stubIPA(t)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	client := freeipa.NewWithHTTPClient(host, "pint", "secret", srv.Client())

	if err := client.Login(); err != nil {
		t.Fatalf("Login() error: %v", err)
	}
}

func TestClient_CAShow(t *testing.T) {
	srv, _, wantDER := stubIPA(t)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	client := freeipa.NewWithHTTPClient(host, "pint", "secret", srv.Client())
	if err := client.Login(); err != nil {
		t.Fatal(err)
	}

	gotDER, err := client.CAShow("ipa")
	if err != nil {
		t.Fatalf("CAShow() error: %v", err)
	}
	if string(gotDER) != string(wantDER) {
		t.Error("CAShow returned unexpected DER bytes")
	}
}

func TestClient_CertRequest(t *testing.T) {
	srv, _, _ := stubIPA(t)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	client := freeipa.NewWithHTTPClient(host, "pint", "secret", srv.Client())
	if err := client.Login(); err != nil {
		t.Fatal(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "testuser"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certDER, err := client.CertRequest("testuser", "EXAMPLE.COM", string(csrPEM), "pint_wifi", "ipa")
	if err != nil {
		t.Fatalf("CertRequest() error: %v", err)
	}
	if _, err := x509.ParseCertificate(certDER); err != nil {
		t.Fatalf("returned bytes are not a valid DER certificate: %v", err)
	}
}
