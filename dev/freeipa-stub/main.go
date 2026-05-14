package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

const profileRadSecServer = "pint_radsec_server"

var serialCounter atomic.Int64

type caEntry struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

// caStore maps FreeIPA CA names to their intermediate CA entries.
// Keys match PINT_IPA_WIRELESS_CA_NAME and PINT_IPA_RADSEC_CA_NAME in .env.dev.
var caStore map[string]*caEntry

func main() {
	dataDir := flag.String("data", "dev/freeipa-stub/data", "directory to persist CA keys and certs")
	wifiCAName := flag.String("wifi-ca", getEnv("PINT_IPA_WIRELESS_CA_NAME", "wireless"), "FreeIPA CA name for WiFi certs (PINT_IPA_WIRELESS_CA_NAME)")
	radSecCAName := flag.String("radsec-ca", getEnv("PINT_IPA_RADSEC_CA_NAME", "radsec"), "FreeIPA CA name for RadSec certs (PINT_IPA_RADSEC_CA_NAME)")
	rootCAName := flag.String("root-ca", getEnv("PINT_IPA_ROOT_CA_NAME", "ipa"), "FreeIPA root CA name (PINT_IPA_ROOT_CA_NAME)")
	flag.Parse()

	serialCounter.Store(time.Now().UnixNano())

	var err error
	caStore, err = loadOrInitCAs(*dataDir, *wifiCAName, *radSecCAName, *rootCAName)
	if err != nil {
		log.Fatalf("CA init: %v", err)
	}

	tlsCert, err := selfSignedTLSCert()
	if err != nil {
		log.Fatalf("TLS cert: %v", err)
	}

	http.HandleFunc("/ipa/session/login_password", handleLogin)
	http.HandleFunc("/ipa/json", handleRPC)

	addr := ":8088"
	server := &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	ln, err := tls.Listen("tcp", addr, server.TLSConfig)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("FreeIPA stub listening on %s (CA data: %s)", addr, *dataDir)
	log.Fatal(server.Serve(ln))
}

// loadOrInitCAs loads persisted CA state from dir, or generates a fresh root +
// two intermediates and persists them. The wifiCAName and radSecCAName are the
// FreeIPA CA names PINT will use; they must match PINT_IPA_CA_NAME and
// PINT_IPA_RADSEC_CA_NAME in .env.dev.
func loadOrInitCAs(dir, wifiCAName, radSecCAName, rootCAName string) (map[string]*caEntry, error) {
	root, err := loadOrCreateCA(dir, "root", "PINT Dev Root CA", nil)
	if err != nil {
		return nil, fmt.Errorf("root CA: %w", err)
	}
	wifi, err := loadOrCreateCA(dir, "wifi", "PINT Dev Wireless CA", root)
	if err != nil {
		return nil, fmt.Errorf("wifi CA: %w", err)
	}
	radsec, err := loadOrCreateCA(dir, "radsec", "PINT Dev RadSec CA", root)
	if err != nil {
		return nil, fmt.Errorf("radsec CA: %w", err)
	}
	log.Printf("CA names: wifi=%q radsec=%q root=%q", wifiCAName, radSecCAName, rootCAName)
	return map[string]*caEntry{
		wifiCAName:   wifi,
		radSecCAName: radsec,
		rootCAName:   root,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadOrCreateCA loads a CA from <dir>/<name>.key and <dir>/<name>.crt, or
// generates and signs a new one. Pass parent=nil to create a self-signed root.
func loadOrCreateCA(dir, name, cn string, parent *caEntry) (*caEntry, error) {
	keyPath := filepath.Join(dir, name+".key")
	certPath := filepath.Join(dir, name+".crt")

	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	if keyErr == nil && certErr == nil {
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("invalid PEM in %s", keyPath)
		}
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return nil, fmt.Errorf("invalid PEM in %s", certPath)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		log.Printf("loaded CA %q from %s", name, dir)
		return &caEntry{key: key, cert: cert, der: certBlock.Bytes}, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serialCounter.Add(1)),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"CSH.RIT.EDU"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	signerCert := tmpl
	signerKey := key
	if parent != nil {
		signerCert = parent.cert
		signerKey = parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	cert, _ := x509.ParseCertificate(der)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}), 0644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	log.Printf("generated CA %q, persisted to %s", name, dir)
	return &caEntry{key: key, cert: cert, der: der}, nil
}

// selfSignedTLSCert generates an ephemeral self-signed cert for localhost.
// PINT_IPA_SKIP_TLS_VERIFY=true means PINT won't validate it.
func selfSignedTLSCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: "stub-session", Path: "/"})
	w.WriteHeader(http.StatusOK)
}

func handleRPC(w http.ResponseWriter, r *http.Request) {
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	method, _ := req["method"].(string)
	w.Header().Set("Content-Type", "application/json")

	switch method {
	case "ca_show":
		params, _ := req["params"].([]interface{})
		if len(params) < 1 {
			http.Error(w, "missing params", http.StatusBadRequest)
			return
		}
		args, _ := params[0].([]interface{})
		if len(args) < 1 {
			http.Error(w, "missing CA name", http.StatusBadRequest)
			return
		}
		caName := fmt.Sprintf("%v", args[0])
		ca, ok := caStore[caName]
		if !ok {
			keys := make([]string, 0, len(caStore))
			for k := range caStore {
				keys = append(keys, k)
			}
			log.Printf("ca_show: unknown CA %q (have: %v)", caName, keys)
			http.Error(w, "unknown CA: "+caName, http.StatusBadRequest)
			return
		}
		log.Printf("ca_show: serving CA %q", caName)
		json.NewEncoder(w).Encode(rpcOK(map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(ca.der),
		}))

	case "cert_request":
		params, _ := req["params"].([]interface{})
		if len(params) < 2 {
			http.Error(w, "missing params", http.StatusBadRequest)
			return
		}
		args, _ := params[0].([]interface{})
		if len(args) < 1 {
			http.Error(w, "missing CSR", http.StatusBadRequest)
			return
		}
		kwargs, _ := params[1].(map[string]interface{})
		caName, _ := kwargs["cacn"].(string)
		profileID, _ := kwargs["profile_id"].(string)

		ca, ok := caStore[caName]
		if !ok {
			http.Error(w, "unknown CA: "+caName, http.StatusBadRequest)
			return
		}

		csrPEM := []byte(fmt.Sprintf("%v", args[0]))
		leafDER, err := signCSR(csrPEM, profileID, ca)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(rpcOK(map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(leafDER),
		}))

	case "cert_revoke":
		log.Printf("cert_revoke: stub, no-op")
		json.NewEncoder(w).Encode(rpcOK(map[string]interface{}{"result": true}))

	default:
		http.Error(w, "unknown method: "+method, http.StatusBadRequest)
	}
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	for len(csrPEM) > 0 {
		var block *pem.Block
		block, csrPEM = pem.Decode(csrPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE REQUEST" {
			return x509.ParseCertificateRequest(block.Bytes)
		}
	}
	return nil, fmt.Errorf("no CERTIFICATE REQUEST PEM block found")
}

func signCSR(csrPEM []byte, profileID string, ca *caEntry) ([]byte, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	eku := x509.ExtKeyUsageClientAuth
	validity := 5 * 365 * 24 * time.Hour
	var dnsNames []string
	if profileID == profileRadSecServer {
		eku = x509.ExtKeyUsageServerAuth
		validity = 90 * 24 * time.Hour
		// SANs are required by RFC 6125 / Go 1.15+ / OpenSSL for server certs.
		if cn := csr.Subject.CommonName; cn != "" {
			dnsNames = []string{cn}
		}
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if profileID == profileRadSecServer {
		keyUsage |= x509.KeyUsageKeyAgreement
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serialCounter.Add(1)),
		Subject:      csr.Subject,
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
}

func rpcOK(result interface{}) map[string]interface{} {
	return map[string]interface{}{
		"id":    0,
		"error": nil,
		"result": map[string]interface{}{
			"result":  result,
			"summary": "",
		},
	}
}
