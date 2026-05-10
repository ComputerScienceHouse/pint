package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

var (
	caKey  *rsa.PrivateKey
	caCert *x509.Certificate
	caDER  []byte
)

func main() {
	var err error
	caKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PINT Dev Stub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	caCert, _ = x509.ParseCertificate(caDER)
	log.Println("stub CA generated")

	http.HandleFunc("/ipa/session/login_password", handleLogin)
	http.HandleFunc("/ipa/json", handleRPC)

	addr := ":8088"
	log.Printf("FreeIPA stub listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
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
		json.NewEncoder(w).Encode(rpcOK(map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(caDER),
		}))

	case "cert_request":
		params, _ := req["params"].([]interface{})
		if len(params) < 1 {
			http.Error(w, "missing params", http.StatusBadRequest)
			return
		}
		args, _ := params[0].([]interface{})
		if len(args) < 1 {
			http.Error(w, "missing CSR", http.StatusBadRequest)
			return
		}
		csrPEM := []byte(fmt.Sprintf("%v", args[0]))
		leafDER, err := signCSR(csrPEM)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(rpcOK(map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(leafDER),
		}))

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

func signCSR(csrPEM []byte) ([]byte, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
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
