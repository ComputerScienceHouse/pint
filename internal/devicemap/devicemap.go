// internal/devicemap/devicemap.go
package devicemap

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const secretKey = "device-map.json"

// DeviceInfo holds what we know about a device at enrollment time.
type DeviceInfo struct {
	Username      string    `json:"username,omitempty"`
	DeviceName    string    `json:"device_name,omitempty"`
	Platform      string    `json:"platform,omitempty"`
	IsSCEP        bool      `json:"is_scep,omitempty"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	LastRenewedAt time.Time `json:"last_renewed_at,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

// DeviceMap is a Kubernetes-Secret-backed map of cert serial → DeviceInfo.
// A process-local mutex serializes concurrent writes within the same replica.
// Cross-replica conflicts are handled via Kubernetes resourceVersion optimistic concurrency:
// each write reads the current secret, modifies it, and retries on 409 Conflict.
type DeviceMap struct {
	mu         sync.Mutex
	k8s        kubernetes.Interface
	namespace  string
	secretName string
}

func New(k8s kubernetes.Interface, namespace, secretName string) *DeviceMap {
	return &DeviceMap{k8s: k8s, namespace: namespace, secretName: secretName}
}

// Set stores or replaces the DeviceInfo for the given cert serial number.
func (m *DeviceMap) Set(ctx context.Context, serial string, info DeviceInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.modify(ctx, func(entries map[string]DeviceInfo) {
		entries[serial] = info
	})
}

// Get returns the DeviceInfo for a single cert serial number.
func (m *DeviceMap) Get(ctx context.Context, serial string) (DeviceInfo, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, entries, err := m.loadSecret(ctx)
	if err != nil {
		return DeviceInfo{}, false, err
	}
	info, ok := entries[serial]
	return info, ok, nil
}

// All returns a copy of the full serial → DeviceInfo map.
func (m *DeviceMap) All(ctx context.Context) (map[string]DeviceInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, entries, err := m.loadSecret(ctx)
	return entries, err
}

// Replace atomically removes oldSerial and stores newSerial with info.
// Returns the previous DeviceInfo for oldSerial (zero value if not found).
func (m *DeviceMap) Replace(ctx context.Context, oldSerial, newSerial string, info DeviceInfo) (DeviceInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev DeviceInfo
	err := m.modify(ctx, func(entries map[string]DeviceInfo) {
		prev = entries[oldSerial]
		delete(entries, oldSerial)
		entries[newSerial] = info
	})
	return prev, err
}

// Delete removes the device map entry for the given cert serial number.
func (m *DeviceMap) Delete(ctx context.Context, serial string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.modify(ctx, func(entries map[string]DeviceInfo) {
		delete(entries, serial)
	})
}

// modify reads the current secret, applies mutate, and writes it back with retry-on-conflict.
// Must be called with m.mu held.
func (m *DeviceMap) modify(ctx context.Context, mutate func(map[string]DeviceInfo)) error {
	const maxRetries = 5
	for range maxRetries {
		secret, entries, err := m.loadSecret(ctx)
		if err != nil {
			return err
		}
		mutate(entries)
		err = m.saveSecret(ctx, secret, entries)
		if err == nil {
			return nil
		}
		if !errors.IsConflict(err) && !errors.IsAlreadyExists(err) {
			return err
		}
		// Conflict or AlreadyExists: another writer raced us; retry with fresh data.
	}
	return fmt.Errorf("devicemap: exceeded max retries on conflict")
}

// loadSecret fetches the K8s secret and deserializes the device map.
// Returns (nil secret, empty map, nil) when the secret does not exist yet.
func (m *DeviceMap) loadSecret(ctx context.Context) (*corev1.Secret, map[string]DeviceInfo, error) {
	secret, err := m.k8s.CoreV1().Secrets(m.namespace).Get(ctx, m.secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, make(map[string]DeviceInfo), nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get secret %s: %w", m.secretName, err)
	}
	data, ok := secret.Data[secretKey]
	if !ok {
		return secret, make(map[string]DeviceInfo), nil
	}
	var entries map[string]DeviceInfo
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, nil, fmt.Errorf("unmarshal device map: %w", err)
	}
	return secret, entries, nil
}

// saveSecret serializes entries and writes them back to Kubernetes.
// When secret is nil (the secret didn't exist at load time) it attempts a Create.
func (m *DeviceMap) saveSecret(ctx context.Context, secret *corev1.Secret, entries map[string]DeviceInfo) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if secret == nil {
		_, err = m.k8s.CoreV1().Secrets(m.namespace).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: m.secretName, Namespace: m.namespace},
			Data:       map[string][]byte{secretKey: data},
		}, metav1.CreateOptions{})
		return err
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[secretKey] = data
	_, err = m.k8s.CoreV1().Secrets(m.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}
