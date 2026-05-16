package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/gin-gonic/gin"
	sceppkg "github.com/smallstep/scep"
	"go.uber.org/zap"
)

// getCACaps response advertises POST support so clients don't fall back to
// GET-with-base64-message for PKIOperation.
const caCaps = "POSTPKIOperation\nSHA-256\nAES\n"

// Handler handles SCEP GetCACert and PKIOperation requests.
type Handler struct {
	log         *zap.Logger
	store       *ChallengeStore
	ipaClient   *freeipa.Client
	caName      string
	certProfile string
	raCert      *x509.Certificate
	raKey       *rsa.PrivateKey
	// RA cert + wireless CA + root CA, ordered for GetCACert response.
	// RA cert must be first so clients use it for envelope encryption.
	caCerts []*x509.Certificate
}

func NewHandler(log *zap.Logger, store *ChallengeStore, ipaClient *freeipa.Client, caName, certProfile string, raCert *x509.Certificate, raKey *rsa.PrivateKey, caDER, rootCACertDER []byte) (*Handler, error) {
	wifiCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse wifi CA: %w", err)
	}
	rootCA, err := x509.ParseCertificate(rootCACertDER)
	if err != nil {
		return nil, fmt.Errorf("parse root CA: %w", err)
	}
	return &Handler{
		log:         log,
		store:       store,
		ipaClient:   ipaClient,
		caName:      caName,
		certProfile: certProfile,
		raCert:      raCert,
		raKey:       raKey,
		caCerts:     []*x509.Certificate{raCert, wifiCA, rootCA},
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
	deg, err := sceppkg.DegenerateCertificates(h.caCerts)
	if err != nil {
		h.log.Error("scep: GetCACert failed", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(http.StatusOK, "application/x-x509-ca-ra-cert", deg)
}

func (h *Handler) pkiOperation(c *gin.Context) {
	var body []byte
	var err error
	if c.Request.Method == http.MethodGet {
		// SCEP GET fallback: message is base64-encoded in the query param.
		body, err = base64.StdEncoding.DecodeString(c.Query("message"))
	} else {
		body, err = io.ReadAll(c.Request.Body)
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

	username, ok := h.store.Validate(msg.CSRReqMessage.ChallengePassword)
	if !ok {
		h.log.Warn("scep: invalid or expired challenge")
		h.sendFail(c, msg, sceppkg.BadRequest)
		return
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

	h.log.Info("scep: certificate issued", zap.String("username", username), zap.String("cn", issuedCert.Subject.CommonName))
	c.Data(http.StatusOK, "application/x-pki-message", resp.Raw)
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
