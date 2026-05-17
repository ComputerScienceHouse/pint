package scep

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/devicemap"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/gin-gonic/gin"
	"github.com/smallstep/pkcs7"
	sceppkg "github.com/smallstep/scep"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// getCACaps response advertises POST support so clients don't fall back to
// GET-with-base64-message for PKIOperation.
const caCaps = "POSTPKIOperation\nSHA-256\nAES\n"

func init() {
	// DES is disabled in OpenSSL 3+ — force AES for all SCEP envelope encryption.
	// Set once at package import rather than per-handler to avoid a data race.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
}

// Handler handles SCEP GetCACert and PKIOperation requests.
type Handler struct {
	log         *zap.Logger
	store       *ChallengeStore
	ipaClient   *freeipa.Client
	deviceMap   *devicemap.DeviceMap
	caName      string
	certProfile string
	raCert      *x509.Certificate
	raKey       *rsa.PrivateKey
	wifiCA      *x509.Certificate // verifies RenewalReq signer certs
	rootCA      *x509.Certificate
	// RA cert + wireless CA + root CA, ordered for GetCACert response.
	// RA cert must be first so clients use it for envelope encryption.
	caCerts    []*x509.Certificate
	degCACerts []byte // precomputed GetCACert response body
}

func NewHandler(log *zap.Logger, store *ChallengeStore, ipaClient *freeipa.Client, dm *devicemap.DeviceMap, caName, certProfile string, raCert *x509.Certificate, raKey *rsa.PrivateKey, caDER, rootCACertDER []byte) (*Handler, error) {
	wifiCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse wifi CA: %w", err)
	}
	rootCA, err := x509.ParseCertificate(rootCACertDER)
	if err != nil {
		return nil, fmt.Errorf("parse root CA: %w", err)
	}
	caCerts := []*x509.Certificate{raCert, wifiCA, rootCA}
	deg, err := sceppkg.DegenerateCertificates(caCerts)
	if err != nil {
		return nil, fmt.Errorf("build CA cert response: %w", err)
	}
	return &Handler{
		log:         log,
		store:       store,
		ipaClient:   ipaClient,
		deviceMap:   dm,
		caName:      caName,
		certProfile: certProfile,
		raCert:      raCert,
		raKey:       raKey,
		wifiCA:      wifiCA,
		rootCA:      rootCA,
		caCerts:     caCerts,
		degCACerts:  deg,
	}, nil
}

// Register adds GET and POST /scep to r. No auth middleware — iOS calls these
// without a session cookie; the challenge password in the enrollment request is the auth.
func (h *Handler) Register(r gin.IRouter) {
	r.GET("/scep", h.handle)
	r.POST("/scep", h.handle)
}

func (h *Handler) handle(c *gin.Context) {
	switch c.Query("operation") {
	case "GetCACaps":
		c.Data(http.StatusOK, "text/plain", []byte(caCaps))
	case "GetCACert":
		h.getCACert(c)
	case "PKIOperation":
		h.pkiOperation(c)
	default:
		c.Status(http.StatusBadRequest)
	}
}

func (h *Handler) getCACert(c *gin.Context) {
	c.Data(http.StatusOK, "application/x-x509-ca-ra-cert", h.degCACerts)
}

func (h *Handler) pkiOperation(c *gin.Context) {
	var body []byte
	var err error
	if c.Request.Method == http.MethodGet {
		// SCEP GET fallback: message is base64-encoded in the query param.
		body, err = base64.StdEncoding.DecodeString(c.Query("message"))
	} else {
		body, err = io.ReadAll(io.LimitReader(c.Request.Body, 64*1024))
	}
	if err != nil || len(body) == 0 {
		c.Status(http.StatusBadRequest)
		return
	}

	msg, err := sceppkg.ParsePKIMessage(body)
	if err != nil {
		h.log.Warn("scep: parse PKIMessage failed", zap.Error(err))
		c.Status(http.StatusBadRequest)
		return
	}

	if msg.MessageType != sceppkg.PKCSReq && msg.MessageType != sceppkg.RenewalReq {
		h.log.Warn("scep: unsupported message type", zap.String("type", string(msg.MessageType)))
		c.Status(http.StatusBadRequest)
		return
	}

	if err := msg.DecryptPKIEnvelope(h.raCert, h.raKey); err != nil {
		h.log.Warn("scep: decrypt PKIEnvelope failed", zap.Error(err))
		h.sendFail(c, msg, sceppkg.BadMessageCheck)
		return
	}

	var username, deviceName, platform string
	var oldCertSerial *big.Int

	switch msg.MessageType {
	case sceppkg.PKCSReq:
		// Some clients (sscep, iOS) send PKCSReq signed with their existing cert
		// rather than a self-signed temp cert when renewing. Detect this by
		// checking whether the signer cert verifies against our WiFi CA chain;
		// if it does, treat it as a renewal without requiring a challenge password.
		if signerCert, err := clientCertFromSCEPMessage(msg.Raw); err == nil {
			if h.verifyWiFiCert(signerCert) == nil {
				username = signerCert.Subject.CommonName
				oldCertSerial = signerCert.SerialNumber
				h.log.Info("scep: PKCSReq renewal (signed with existing cert)",
					zap.String("username", username), zap.String("old_serial", oldCertSerial.String()))
				break
			}
		}
		// Initial enrollment: validate challenge password.
		var ok bool
		username, deviceName, platform, ok = h.store.Validate(msg.CSRReqMessage.ChallengePassword)
		if !ok {
			h.log.Warn("scep: invalid or expired challenge")
			h.sendFail(c, msg, sceppkg.BadRequest)
			return
		}
		if platform == "" {
			platform = "ios"
		}

	case sceppkg.RenewalReq:
		signerCert, err := clientCertFromSCEPMessage(msg.Raw)
		if err != nil {
			h.log.Warn("scep: renewal signer cert extraction failed", zap.Error(err))
			h.sendFail(c, msg, sceppkg.BadMessageCheck)
			return
		}
		if err := h.verifyWiFiCert(signerCert); err != nil {
			h.log.Warn("scep: renewal signer cert not trusted", zap.Error(err))
			h.sendFail(c, msg, sceppkg.BadRequest)
			return
		}
		username = signerCert.Subject.CommonName
		oldCertSerial = signerCert.SerialNumber
		h.log.Info("scep: renewal request", zap.String("username", username), zap.String("old_serial", oldCertSerial.String()))
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: msg.CSRReqMessage.CSR.Raw})
	certDER, err := h.ipaClient.CertRequest(username, string(csrPEM), h.caName, h.certProfile)
	if err != nil {
		h.log.Error("scep: cert_request failed", zap.String("username", username), zap.Error(err))
		h.sendFail(c, msg, sceppkg.BadRequest)
		return
	}

	issuedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		h.log.Error("scep: parse issued cert failed", zap.Error(err))
		h.sendFail(c, msg, sceppkg.BadRequest)
		return
	}

	resp, err := msg.Success(h.raCert, h.raKey, issuedCert)
	if err != nil {
		h.log.Error("scep: build success response failed", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	newSerial := issuedCert.SerialNumber.String()
	h.log.Info("scep: certificate issued", zap.String("username", username), zap.String("serial", newSerial))

	if h.deviceMap != nil {
		now := time.Now()
		info := devicemap.DeviceInfo{
			Username:   username,
			DeviceName: deviceName,
			Platform:   platform,
			IsSCEP:     true,
			EnrolledAt: now,
			ExpiresAt:  issuedCert.NotAfter,
		}
		if oldCertSerial != nil {
			prev, err := h.deviceMap.Replace(c.Request.Context(), oldCertSerial.String(), newSerial, info)
			if err != nil {
				h.log.Error("scep: failed to update device map on renewal", zap.String("serial", newSerial), zap.Error(err))
			}
			// Carry forward metadata the renewal request didn't supply.
			if info.DeviceName == "" {
				info.DeviceName = prev.DeviceName
			}
			if info.Platform == "" {
				info.Platform = prev.Platform
			}
			if !prev.EnrolledAt.IsZero() {
				info.EnrolledAt = prev.EnrolledAt
			}
			info.LastRenewedAt = now
			if err := h.deviceMap.Set(c.Request.Context(), newSerial, info); err != nil {
				h.log.Error("scep: failed to update device info on renewal", zap.String("serial", newSerial), zap.Error(err))
			}
		} else if err := h.deviceMap.Set(c.Request.Context(), newSerial, info); err != nil {
			h.log.Error("scep: failed to record device info", zap.String("serial", newSerial), zap.Error(err))
		}
	}

	if oldCertSerial != nil {
		if !oldCertSerial.IsInt64() {
			h.log.Error("scep: old cert serial too large for int64, skipping revocation", zap.String("serial", oldCertSerial.String()))
		} else if err := h.ipaClient.CertRevoke(oldCertSerial.Int64(), h.caName, 0); err != nil {
			h.log.Error("scep: failed to revoke old cert during renewal", zap.String("serial", oldCertSerial.String()), zap.Error(err))
		} else {
			h.log.Info("scep: revoked old cert during renewal", zap.String("serial", oldCertSerial.String()))
		}
	}

	c.Data(http.StatusOK, "application/x-pki-message", resp.Raw)
}

// clientCertFromSCEPMessage returns the first non-CA certificate embedded in the
// SCEP message's outer CMS SignedData — the signer cert for PKCSReq/RenewalReq.
// Re-parsing msg.Raw is necessary because the scep library does not expose p7.Certificates.
func clientCertFromSCEPMessage(raw []byte) (*x509.Certificate, error) {
	p7, err := pkcs7.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs7: %w", err)
	}
	for _, cert := range p7.Certificates {
		if !cert.IsCA {
			return cert, nil
		}
	}
	return nil, errors.New("no client certificate found in SCEP message")
}

// verifyWiFiCert checks that cert was issued by the WiFi CA chain and is not revoked.
// Revocation is checked via OCSP using the URL embedded in the cert's AIA extension.
func (h *Handler) verifyWiFiCert(cert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(h.rootCA)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(h.wifiCA)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return err
	}
	return h.checkOCSP(cert, h.wifiCA)
}

// checkOCSP queries the OCSP URL from cert's AIA extension and returns an error
// if the cert is revoked or the check cannot be completed.
func (h *Handler) checkOCSP(cert, issuer *x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		h.log.Warn("scep: cert has no OCSP URL, skipping revocation check",
			zap.String("serial", cert.SerialNumber.String()))
		return nil
	}

	reqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("ocsp: build request: %w", err)
	}

	resp, err := http.Post(cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(reqBytes)) //nolint:noctx
	if err != nil {
		return fmt.Errorf("ocsp: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("ocsp: read response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return fmt.Errorf("ocsp: parse response: %w", err)
	}

	if ocspResp.Status == ocsp.Revoked {
		return fmt.Errorf("ocsp: certificate %s is revoked", cert.SerialNumber.String())
	}
	return nil
}

func (h *Handler) sendFail(c *gin.Context, msg *sceppkg.PKIMessage, info sceppkg.FailInfo) {
	resp, err := msg.Fail(h.raCert, h.raKey, info)
	if err != nil {
		h.log.Error("scep: build fail response failed", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(http.StatusOK, "application/x-pki-message", resp.Raw)
}
