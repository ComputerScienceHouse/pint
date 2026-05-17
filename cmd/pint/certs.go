package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/certmgr"
	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	internscep "github.com/ComputerScienceHouse/pint/internal/scep"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const renewBefore = 30 * 24 * time.Hour

// ── RadSec server cert ────────────────────────────────────────────────────────

type radSecServerCert struct {
	log          *zap.Logger
	ipaClient    *freeipa.Client
	cfg          *config.Config
	k8s          kubernetes.Interface
	radSecCAPEM  []byte
}

func newRadSecServerCert(log *zap.Logger, ipa *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, radSecCAPEM []byte) certmgr.ManagedCert {
	return &radSecServerCert{log: log, ipaClient: ipa, cfg: cfg, k8s: k8s, radSecCAPEM: radSecCAPEM}
}

func (c *radSecServerCert) Name() string { return "RadSec server" }
func (c *radSecServerCert) SecretRef() (string, string, string) {
	return c.cfg.Namespace, c.cfg.RadSecCertSecret, "tls.crt"
}
func (c *radSecServerCert) ShouldRenew(existingPEM []byte) bool {
	return shouldRenewPEM(existingPEM, renewBefore)
}
func (c *radSecServerCert) Issue(ctx context.Context, _ []byte) ([]byte, error) {
	privKey, csrPEM, err := profile.GenerateKeyAndCSR(c.cfg.IPAServiceHostname)
	if err != nil {
		return nil, fmt.Errorf("generate radsec key/csr: %w", err)
	}
	certDER, err := c.ipaClient.CertRequest(c.cfg.IPAPrincipal, string(csrPEM), c.cfg.RadSecCAName, c.cfg.RadSecServerCertProfile)
	if err != nil {
		return nil, fmt.Errorf("cert_request radsec: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := profile.MarshalECKeyPEM(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal radsec ec key: %w", err)
	}
	if err := radius.WriteRadSecServerCert(ctx, c.k8s, c.cfg.Namespace, c.cfg.RadSecCertSecret, c.cfg.FreeRADIUSDeployment, certPEM, keyPEM, c.radSecCAPEM); err != nil {
		return nil, fmt.Errorf("write radsec cert: %w", err)
	}
	return certPEM, nil
}
func (c *radSecServerCert) AfterRenew(_ context.Context, _ []byte) error { return nil }

// ── EAP server cert ───────────────────────────────────────────────────────────

type eapServerCert struct {
	log       *zap.Logger
	ipaClient *freeipa.Client
	cfg       *config.Config
	k8s       kubernetes.Interface
	wifiCAPEM []byte
}

func newEAPServerCert(log *zap.Logger, ipa *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, wifiCAPEM []byte) certmgr.ManagedCert {
	return &eapServerCert{log: log, ipaClient: ipa, cfg: cfg, k8s: k8s, wifiCAPEM: wifiCAPEM}
}

func (c *eapServerCert) Name() string { return "EAP server" }
func (c *eapServerCert) SecretRef() (string, string, string) {
	return c.cfg.Namespace, c.cfg.EAPCertSecret, "eap.crt"
}
func (c *eapServerCert) ShouldRenew(existingPEM []byte) bool {
	if len(existingPEM) == 0 {
		return true
	}
	block, rest := pem.Decode(existingPEM)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	if time.Until(cert.NotAfter) <= renewBefore {
		return true
	}
	// EAPMigrateLegacyLeaf: upgrade leaf-only certs to include the CA chain.
	// RFC 5246 §7.4.2 requires servers to supply intermediates; iOS won't fetch them.
	if c.cfg.EAPMigrateLegacyLeaf && len(rest) == 0 {
		return true
	}
	// iOS 13+ requires a DNS SAN for EAP-TLS server identity.
	if len(cert.DNSNames) == 0 {
		return true
	}
	return false
}
func (c *eapServerCert) Issue(ctx context.Context, existingPEM []byte) ([]byte, error) {
	if chainPEM, ok, err := c.tryMigrateLeafOnly(ctx, existingPEM); err != nil || ok {
		return chainPEM, err
	}

	privKey, csrPEM, err := profile.GenerateKeyAndCSR(c.cfg.IPAServiceHostname, c.cfg.IPAServiceHostname)
	if err != nil {
		return nil, fmt.Errorf("generate eap key/csr: %w", err)
	}
	certDER, err := c.ipaClient.CertRequest(c.cfg.IPAPrincipal, string(csrPEM), c.cfg.IPAWirelessCAName, c.cfg.EAPCertProfile)
	if err != nil {
		return nil, fmt.Errorf("cert_request eap: %w", err)
	}
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), c.wifiCAPEM...)
	keyPEM, err := profile.MarshalECKeyPEM(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal eap ec key: %w", err)
	}
	if err := radius.WriteEAPServerCert(ctx, c.k8s, c.cfg.Namespace, c.cfg.EAPCertSecret, c.cfg.FreeRADIUSDeployment, chainPEM, keyPEM, c.wifiCAPEM); err != nil {
		return nil, fmt.Errorf("write eap cert: %w", err)
	}
	return chainPEM, nil
}

// tryMigrateLeafOnly appends the WiFi CA chain to a leaf-only EAP cert without reissuing.
// Returns (chainPEM, true, nil) on success, (nil, false, nil) when migration doesn't apply,
// or (nil, false, err) on failure.
func (c *eapServerCert) tryMigrateLeafOnly(ctx context.Context, existingPEM []byte) ([]byte, bool, error) {
	if !c.cfg.EAPMigrateLegacyLeaf || len(existingPEM) == 0 {
		return nil, false, nil
	}
	block, rest := pem.Decode(existingPEM)
	if block == nil || len(rest) > 0 {
		return nil, false, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || time.Until(cert.NotAfter) <= renewBefore || len(cert.DNSNames) == 0 {
		return nil, false, nil
	}
	secret, err := c.k8s.CoreV1().Secrets(c.cfg.Namespace).Get(ctx, c.cfg.EAPCertSecret, metav1.GetOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("get eap secret for leaf migration: %w", err)
	}
	chainPEM := append(existingPEM, c.wifiCAPEM...)
	if err := radius.WriteEAPServerCert(ctx, c.k8s, c.cfg.Namespace, c.cfg.EAPCertSecret, c.cfg.FreeRADIUSDeployment, chainPEM, secret.Data["eap.key"], c.wifiCAPEM); err != nil {
		return nil, false, fmt.Errorf("write eap cert (leaf migration): %w", err)
	}
	c.log.Info("eap.crt: appended CA chain to leaf-only cert (legacy migration)")
	return chainPEM, true, nil
}
func (c *eapServerCert) AfterRenew(_ context.Context, _ []byte) error { return nil }

// ── Profile signing cert ──────────────────────────────────────────────────────

type profileSigningCert struct {
	log                  *zap.Logger
	ipaClient            *freeipa.Client
	cfg                  *config.Config
	k8s                  kubernetes.Interface
	codeSigningCACertDER []byte
	onRenew              func(*profile.Signer) // called after renewal to hot-swap in-memory signer
}

func newProfileSigningCert(log *zap.Logger, ipa *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, codeSigningCACertDER []byte, onRenew func(*profile.Signer)) certmgr.ManagedCert {
	return &profileSigningCert{log: log, ipaClient: ipa, cfg: cfg, k8s: k8s, codeSigningCACertDER: codeSigningCACertDER, onRenew: onRenew}
}

func (c *profileSigningCert) Name() string { return "profile signing" }
func (c *profileSigningCert) SecretRef() (string, string, string) {
	return c.cfg.Namespace, c.cfg.ProfileSigningCertSecret, "tls.crt"
}
func (c *profileSigningCert) ShouldRenew(existingPEM []byte) bool {
	return shouldRenewPEM(existingPEM, renewBefore)
}
func (c *profileSigningCert) Issue(ctx context.Context, _ []byte) ([]byte, error) {
	privKey, csrPEM, err := profile.GenerateKeyAndCSR(c.cfg.IPAServiceHostname)
	if err != nil {
		return nil, fmt.Errorf("generate key/csr: %w", err)
	}
	certDER, err := c.ipaClient.CertRequest(c.cfg.IPAPrincipal, string(csrPEM), c.cfg.CodeSigningCAName, c.cfg.CodeSigningCertProfile)
	if err != nil {
		return nil, fmt.Errorf("cert_request (profile signing): %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := profile.MarshalECKeyPEM(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal profile signing ec key: %w", err)
	}

	signingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: c.cfg.ProfileSigningCertSecret, Namespace: c.cfg.Namespace},
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
	}
	if err := radius.UpsertSecret(ctx, c.k8s, signingSecret); err != nil {
		return nil, fmt.Errorf("store profile signing cert: %w", err)
	}
	return certPEM, nil
}
func (c *profileSigningCert) AfterRenew(ctx context.Context, certPEM []byte) error {
	secret, err := c.k8s.CoreV1().Secrets(c.cfg.Namespace).Get(ctx, c.cfg.ProfileSigningCertSecret, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read profile signing cert for hot-swap: %w", err)
	}
	signer, err := profileSignerFromPEM(certPEM, secret.Data["tls.key"], c.codeSigningCACertDER)
	if err != nil {
		return fmt.Errorf("build signer: %w", err)
	}
	c.onRenew(signer)
	c.log.Info("profile signing cert hot-swapped in memory")
	return nil
}

// ── SCEP RA cert ──────────────────────────────────────────────────────────────

// loadOrGenerateSCEPRACert loads or generates the self-signed SCEP RA cert.
// The cert does not expire in normal operation; no renewal watcher is needed.
func loadOrGenerateSCEPRACert(ctx context.Context, log *zap.Logger, k8sClient kubernetes.Interface, cfg *config.Config) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	secret, err := k8sClient.CoreV1().Secrets(cfg.Namespace).Get(ctx, cfg.SCEPRACertSecret, metav1.GetOptions{})
	if err == nil {
		certPEM := secret.Data["tls.crt"]
		keyPEM := secret.Data["tls.key"]
		if len(certPEM) > 0 && len(keyPEM) > 0 {
			cert, key, parseErr := internscep.ParseRACert(certPEM, keyPEM)
			if parseErr == nil {
				log.Info("reusing existing SCEP RA cert", zap.String("expires", cert.NotAfter.Format("2006-01-02")))
				return cert, key, cert.Raw, nil
			}
		}
	}

	cert, key, certPEM, keyPEM, genErr := internscep.GenerateRACert()
	if genErr != nil {
		return nil, nil, nil, fmt.Errorf("generate SCEP RA cert: %w", genErr)
	}

	raSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: cfg.SCEPRACertSecret, Namespace: cfg.Namespace},
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
	}
	if err := radius.UpsertSecret(ctx, k8sClient, raSecret); err != nil {
		return nil, nil, nil, fmt.Errorf("store SCEP RA cert: %w", err)
	}
	log.Info("generated new SCEP RA cert")
	return cert, key, cert.Raw, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func shouldRenewPEM(existingPEM []byte, d time.Duration) bool {
	if len(existingPEM) == 0 {
		return true
	}
	block, _ := pem.Decode(existingPEM)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) <= d
}

func profileSignerFromPEM(certPEM, keyPEM, codeSigningCACertDER []byte) (*profile.Signer, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("decode cert PEM: empty block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode key PEM: empty block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC key: %w", err)
	}
	s := &profile.Signer{Cert: cert, Key: key}
	if len(codeSigningCACertDER) > 0 {
		ca, err := x509.ParseCertificate(codeSigningCACertDER)
		if err != nil {
			return nil, fmt.Errorf("parse code signing CA: %w", err)
		}
		s.Intermediates = []*x509.Certificate{ca}
	}
	return s, nil
}

func logCACert(log *zap.Logger, name string, der []byte) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Warn("CA cert parse failed", zap.String("ca", name), zap.Error(err))
		return
	}
	remaining := time.Until(cert.NotAfter).Truncate(time.Hour)
	log.Info("CA cert loaded",
		zap.String("ca", name),
		zap.String("valid_until", cert.NotAfter.Format("2006-01-02")),
		zap.String("remaining", formatDuration(remaining)),
	)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "EXPIRED"
	}
	days := int(d.Hours()) / 24
	if days >= 365 {
		return fmt.Sprintf("%dy %dd", days/365, days%365)
	}
	return fmt.Sprintf("%dd", days)
}
