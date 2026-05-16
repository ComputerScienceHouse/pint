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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const secretKey = "device-map.json"

// DeviceInfo holds what we know about a device at enrollment time.
type DeviceInfo struct {
	DeviceName string    `json:"device_name,omitempty"`
	Platform   string    `json:"platform,omitempty"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// DeviceMap is a Kubernetes-Secret-backed map of cert serial → DeviceInfo.
// A mutex serializes writes so concurrent SCEP enrollments queue rather than race.
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

	entries, err := m.load(ctx)
	if err != nil {
		return err
	}
	entries[serial] = info
	return m.save(ctx, entries)
}

// All returns a copy of the full serial → DeviceInfo map.
func (m *DeviceMap) All(ctx context.Context) (map[string]DeviceInfo, error) {
	return m.load(ctx)
}

func (m *DeviceMap) load(ctx context.Context) (map[string]DeviceInfo, error) {
	secret, err := m.k8s.CoreV1().Secrets(m.namespace).Get(ctx, m.secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return make(map[string]DeviceInfo), nil
	}
	if err != nil {
		return nil, fmt.Errorf("get secret %s: %w", m.secretName, err)
	}
	data, ok := secret.Data[secretKey]
	if !ok {
		return make(map[string]DeviceInfo), nil
	}
	var entries map[string]DeviceInfo
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("unmarshal device map: %w", err)
	}
	return entries, nil
}

func (m *DeviceMap) save(ctx context.Context, entries map[string]DeviceInfo) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	p, err := json.Marshal(map[string]interface{}{
		"data": map[string][]byte{secretKey: data},
	})
	if err != nil {
		return err
	}
	_, err = m.k8s.CoreV1().Secrets(m.namespace).Patch(ctx, m.secretName, types.MergePatchType, p, metav1.PatchOptions{})
	if !errors.IsNotFound(err) {
		return err
	}
	_, err = m.k8s.CoreV1().Secrets(m.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: m.secretName, Namespace: m.namespace},
		Data:       map[string][]byte{secretKey: data},
	}, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		// Lost the create race with another goroutine; retry the patch.
		_, err = m.k8s.CoreV1().Secrets(m.namespace).Patch(ctx, m.secretName, types.MergePatchType, p, metav1.PatchOptions{})
	}
	return err
}
