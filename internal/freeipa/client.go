// internal/freeipa/client.go
package freeipa

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// RFC 5280 certificate revocation reason codes.
const (
	RevocationReasonSuperseded          = 4
	RevocationReasonCessationOfOperation = 5
)

var errUnauthorized = errors.New("freeipa: 401 unauthorized")

type Client struct {
	host       string
	referer    string
	user       string
	pass       string
	httpClient *http.Client
	mu         sync.Mutex // guards session
	reloginMu  sync.Mutex // serializes re-login attempts
	session    string
}

func New(host, user, pass string, skipTLS bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
	}
	return &Client{
		host:       host,
		referer:    "https://" + host + "/ipa",
		user:       user,
		pass:       pass,
		httpClient: &http.Client{Transport: transport},
	}
}

func NewWithHTTPClient(host, user, pass string, httpClient *http.Client) *Client {
	return &Client{host: host, referer: "https://" + host + "/ipa", user: user, pass: pass, httpClient: httpClient}
}

func (c *Client) Login() error {
	form := url.Values{"user": {c.user}, "password": {c.pass}}
	req, err := http.NewRequest("POST",
		fmt.Sprintf("https://%s/ipa/session/login_password", c.host),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", c.referer)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("freeipa login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("freeipa login: status %d: %s", resp.StatusCode, body)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "ipa_session" {
			c.mu.Lock()
			c.session = cookie.Value
			c.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("freeipa login: ipa_session cookie not set in response")
}

func (c *Client) CAShow(caName string) ([]byte, error) {
	raw, err := c.rpc("ca_show", []interface{}{caName}, map[string]interface{}{"all": true})
	if err != nil {
		return nil, fmt.Errorf("ca_show: %w", err)
	}
	var result caShowResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("ca_show parse: %w", err)
	}
	return base64.StdEncoding.DecodeString(result.Certificate)
}

func (c *Client) CertRequest(principal, csrPEM, caName, profileID string) ([]byte, error) {
	kwargs := map[string]interface{}{
		"principal": principal,
		"cacn":      caName,
	}
	if profileID != "" {
		kwargs["profile_id"] = profileID
		kwargs["add"] = true
	}
	raw, err := c.rpc("cert_request", []interface{}{csrPEM}, kwargs)
	if err != nil {
		return nil, fmt.Errorf("cert_request: %w", err)
	}
	var result certRequestResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("cert_request parse: %w", err)
	}
	return base64.StdEncoding.DecodeString(result.Certificate)
}

// CertRevoke revokes a certificate by serial number.
// reason follows RFC 5280: 0=unspecified, 4=superseded, 5=cessationOfOperation.
// Returns nil if the cert was already revoked or not found, so callers can ignore
// those cases without failing the overall operation.
func (c *Client) CertRevoke(serial int64, caName string, reason int) error {
	_, err := c.rpc("cert_revoke", []interface{}{serial}, map[string]interface{}{
		"revocation_reason": reason,
		"cacn":              caName,
	})
	return err
}

func (c *Client) rpc(method string, args []interface{}, kwargs map[string]interface{}) (json.RawMessage, error) {
	result, err := c.doRPC(method, args, kwargs)
	if err == nil || !errors.Is(err, errUnauthorized) {
		return result, err
	}
	// Serialize re-logins: only one goroutine re-authenticates at a time.
	// Others wait at reloginMu and retry with the refreshed session afterward.
	c.reloginMu.Lock()
	loginErr := c.Login()
	c.reloginMu.Unlock()
	if loginErr != nil {
		return nil, loginErr
	}
	return c.doRPC(method, args, kwargs)
}

func (c *Client) doRPC(method string, args []interface{}, kwargs map[string]interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{
		Method: method,
		Params: []interface{}{args, kwargs},
		ID:     0,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST",
		fmt.Sprintf("https://%s/ipa/json", c.host),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", c.referer)
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	req.AddCookie(&http.Cookie{Name: "ipa_session", Value: session})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errUnauthorized
	}

	var rpcResp rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result.Result, nil
}
