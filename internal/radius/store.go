// internal/radius/store.go
package radius

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RadiusClient represents one home-router RADIUS entry.
type RadiusClient struct {
	Username      string   `json:"username"`
	Secret        string   `json:"secret"`
	IPCIDR        *string  `json:"ip_cidr"`
	CertSerial    string   `json:"cert_serial,omitempty"`
	CertSubject   string   `json:"cert_subject,omitempty"`
	CertIssuer    string   `json:"cert_issuer,omitempty"`
	CertNotBefore string   `json:"cert_not_before,omitempty"`
	CertNotAfter  string   `json:"cert_not_after,omitempty"`
	CertKeyBits   int      `json:"cert_key_bits,omitempty"`
	CertEKUs      []string `json:"cert_ekus,omitempty"`
}

// ClientStore is a Kubernetes-Secret-backed list of RadiusClient entries.
type ClientStore struct {
	k8s        kubernetes.Interface
	namespace  string
	secretName string
	clients    []RadiusClient
}

// NewClientStore creates a store. Call Load before reading or writing.
func NewClientStore(k8s kubernetes.Interface, namespace, secretName string) *ClientStore {
	return &ClientStore{k8s: k8s, namespace: namespace, secretName: secretName}
}

// Load reads the Secret and deserializes the client list. Missing Secret is not an error.
func (s *ClientStore) Load(ctx context.Context) error {
	secret, err := s.k8s.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		s.clients = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret %s: %w", s.secretName, err)
	}
	data, ok := secret.Data["clients.json"]
	if !ok {
		return nil
	}
	// Try bare array (current format) first; fall back to legacy wrapped object.
	if err := json.Unmarshal(data, &s.clients); err != nil {
		var legacy struct {
			Clients []RadiusClient `json:"clients"`
		}
		if err2 := json.Unmarshal(data, &legacy); err2 != nil {
			return fmt.Errorf("unmarshal clients.json: %w", err)
		}
		s.clients = legacy.Clients
	}
	return nil
}

// Save writes the current client list back to the Kubernetes Secret, creating it if needed.
func (s *ClientStore) Save(ctx context.Context) error {
	data, err := json.Marshal(s.clients)
	if err != nil {
		return err
	}
	return upsertSecret(ctx, s.k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.secretName, Namespace: s.namespace},
		Data:       map[string][]byte{"clients.json": data},
	})
}

// Upsert inserts or replaces the entry for client.Username.
func (s *ClientStore) Upsert(client RadiusClient) {
	for i, c := range s.clients {
		if c.Username == client.Username {
			s.clients[i] = client
			return
		}
	}
	s.clients = append(s.clients, client)
}

// Delete removes the entry for username.
func (s *ClientStore) Delete(username string) {
	filtered := make([]RadiusClient, 0, len(s.clients))
	for _, c := range s.clients {
		if c.Username != username {
			filtered = append(filtered, c)
		}
	}
	s.clients = filtered
}

// FindByUsername returns the entry for username, or nil if not found.
func (s *ClientStore) FindByUsername(username string) *RadiusClient {
	for i, c := range s.clients {
		if c.Username == username {
			return &s.clients[i]
		}
	}
	return nil
}

// All returns a copy of the current client list.
func (s *ClientStore) All() []RadiusClient {
	out := make([]RadiusClient, len(s.clients))
	copy(out, s.clients)
	return out
}

// Len returns the number of clients.
func (s *ClientStore) Len() int { return len(s.clients) }
