// internal/radius/reload.go
package radius

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Secret keys in the combined config secret.
const (
	KeyClientsJSON  = "clients.json"
	KeyClientsConf  = "clients.conf"
	KeyStatusSecret = "status-secret"
	KeyStatus       = "status"
	KeyRadSecTLS    = "radsec-tls.conf"
)

// WriteRadiusConfig renders clients.conf from the given client list and patches
// the clients.conf key in the named Kubernetes Secret.
func WriteRadiusConfig(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string, clients []RadiusClient) error {
	return patchSecretKey(ctx, k8s, namespace, secretName, KeyClientsConf, []byte(RenderClientsConf(clients)))
}

// WriteRadSecTLS renders and patches the radsec-tls.conf key in the named K8s Secret.
// Returns (didUpdate, err). didUpdate is false when the existing value is identical.
func WriteRadSecTLS(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string, checkCRL bool) (bool, error) {
	rendered := RenderRadSecTLS(checkCRL)
	existing, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil && string(existing.Data[KeyRadSecTLS]) == rendered {
		return false, nil
	}
	return true, patchSecretKey(ctx, k8s, namespace, secretName, KeyRadSecTLS, []byte(rendered))
}

// WriteRadSecServerCert writes all FreeRADIUS TLS material to the named K8s Secret:
//   - tls.crt / tls.key: server cert presented to RadSec clients and EAP supplicants
//   - ca.pem: RadSec CA chain; verifies connecting router client certificates
//   - wifi-ca.pem: WiFi CA cert; verifies EAP-TLS user certificates
func WriteRadSecServerCert(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string, certPEM, keyPEM, caPEM, wifiCAPEM []byte) error {
	return upsertSecret(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			"tls.crt":     certPEM,
			"tls.key":     keyPEM,
			"ca.pem":      caPEM,
			"wifi-ca.pem": wifiCAPEM,
		},
	})
}

// EnsureConfigSecret creates the combined PINT config secret with all keys
// initialized to safe defaults if it does not already exist.
// Safe to call on every startup — it is a no-op when the secret is present.
func EnsureConfigSecret(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string) error {
	return createIfAbsent(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			KeyClientsJSON:  []byte("[]"),
			KeyClientsConf:  []byte(RenderClientsConf(nil)),
			KeyStatusSecret: []byte(""),
			KeyStatus:       []byte(""),
			KeyRadSecTLS:    []byte(RenderRadSecTLS(true)),
		},
	})
}

// patchSecretKey updates a single key without touching the rest of the secret,
// avoiding races with other components that may patch different keys concurrently.
func patchSecretKey(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, key string, value []byte) error {
	p, err := json.Marshal(map[string]interface{}{
		"data": map[string][]byte{key: value},
	})
	if err != nil {
		return err
	}
	_, err = k8s.CoreV1().Secrets(namespace).Patch(ctx, secretName, types.MergePatchType, p, metav1.PatchOptions{})
	return err
}

// upsertSecret creates or updates a Kubernetes Secret.
func upsertSecret(ctx context.Context, k8s kubernetes.Interface, secret *corev1.Secret) error {
	ns := secret.Namespace
	_, err := k8s.CoreV1().Secrets(ns).Update(ctx, secret, metav1.UpdateOptions{})
	if errors.IsNotFound(err) {
		_, err = k8s.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{})
	}
	return err
}

func createIfAbsent(ctx context.Context, k8s kubernetes.Interface, secret *corev1.Secret) error {
	_, err := k8s.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// Reload triggers a rollout restart of the FreeRADIUS deployment by patching
// the pod template annotation, equivalent to kubectl rollout restart.
func Reload(ctx context.Context, k8s kubernetes.Interface, namespace, deployment string) error {
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().Format(time.RFC3339),
	)
	_, err := k8s.AppsV1().Deployments(namespace).Patch(
		ctx, deployment, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	return err
}
