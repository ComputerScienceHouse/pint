// internal/freeipa/types.go
package freeipa

import "encoding/json"

type rpcRequest struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
	ID     int           `json:"id"`
}

type rpcResponse struct {
	Result *rpcResult `json:"result"`
	Error  *rpcError  `json:"error"`
	ID     int        `json:"id"`
}

type rpcResult struct {
	Result  json.RawMessage `json:"result"`
	Summary string          `json:"summary"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Name    string `json:"name"`
}

// certRequestResult is the inner "result" of a cert_request RPC call.
// FreeIPA returns the leaf certificate as a base64-encoded DER string.
type certRequestResult struct {
	Certificate string `json:"certificate"`
}

// caShowResult is the inner "result" of a ca_show RPC call.
// FreeIPA returns the CA certificate as a base64-encoded DER string.
type caShowResult struct {
	Certificate string `json:"certificate"`
}

// CertInfo is one entry returned by cert_find.
type CertInfo struct {
	SerialNumber  int64  `json:"serial_number"`
	ValidNotAfter string `json:"valid_not_after"`
	Revoked       bool   `json:"revoked"`
}
