// internal/radius/reload.go
package radius

import (
	"context"
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

// WriteRadiusConfig renders clients.conf from the given client list and proxy hosts, patches the
// key in the named Kubernetes Secret, and triggers a FreeRADIUS rollout restart.
func WriteRadiusConfig(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, deployment string, clients []RadiusClient, proxyHosts []string) error {
	if err := patchSecretKey(ctx, k8s, namespace, secretName, KeyClientsConf, []byte(RenderClientsConf(clients, proxyHosts))); err != nil {
		return err
	}
	return Reload(ctx, k8s, namespace, deployment)
}

// WriteRadSecTLS renders and patches the radsec-tls.conf key in the named K8s Secret.
// If the content changed, FreeRADIUS is reloaded. No-op (no reload) when unchanged.
func WriteRadSecTLS(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, deployment string, checkCRL, proxyProtocol bool) error {
	rendered := RenderRadSecTLS(checkCRL, proxyProtocol)
	existing, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil && string(existing.Data[KeyRadSecTLS]) == rendered {
		return nil
	}
	if err := patchSecretKey(ctx, k8s, namespace, secretName, KeyRadSecTLS, []byte(rendered)); err != nil {
		return err
	}
	return Reload(ctx, k8s, namespace, deployment)
}

// WriteEAPServerCert writes the FreeRADIUS EAP-TLS material to the named K8s Secret
// and triggers a FreeRADIUS rollout restart:
//   - eap.crt / eap.key: EAP-TLS server cert (wireless CA-issued; verified by iOS devices)
//   - wifi-ca.pem: WiFi CA chain; verifies EAP-TLS client certs presented by devices
func WriteEAPServerCert(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, deployment string, certPEM, keyPEM, wifiCAPEM []byte) error {
	if err := UpsertSecret(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			"eap.crt":     certPEM,
			"eap.key":     keyPEM,
			"wifi-ca.pem": wifiCAPEM,
		},
	}); err != nil {
		return err
	}
	return Reload(ctx, k8s, namespace, deployment)
}

// WriteRadSecServerCert writes the FreeRADIUS outer RadSec TLS material to the named K8s
// Secret and triggers a FreeRADIUS rollout restart:
//   - tls.crt / tls.key: RadSec TLS cert presented to router clients (RadSec CA-issued)
//   - ca.pem: RadSec CA chain; verifies connecting router client certificates
func WriteRadSecServerCert(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, deployment string, certPEM, keyPEM, caPEM []byte) error {
	if err := UpsertSecret(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
			"ca.pem":  caPEM,
		},
	}); err != nil {
		return err
	}
	return Reload(ctx, k8s, namespace, deployment)
}

// EnsureConfigSecret creates the combined PINT config secret with all keys
// initialized to safe defaults if it does not already exist.
// Safe to call on every startup — it is a no-op when the secret is present.
func EnsureConfigSecret(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string) error {
	return createIfAbsent(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			KeyClientsJSON:  []byte("[]"),
			KeyClientsConf:  []byte(RenderClientsConf(nil, nil)),
			KeyStatusSecret: []byte(""),
			KeyStatus:       []byte(""),
			KeyRadSecTLS:    []byte(RenderRadSecTLS(true, false)),
		},
	})
}

// patchSecretKey sets a single data key in a Kubernetes Secret using read→modify→Update
// with retry-on-conflict so concurrent writers from multiple replicas don't clobber each other.
func patchSecretKey(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, key string, value []byte) error {
	const maxRetries = 5
	for range maxRetries {
		secret, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get secret %s: %w", secretName, err)
		}
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data[key] = value
		_, err = k8s.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if !errors.IsConflict(err) {
			return fmt.Errorf("update secret %s: %w", secretName, err)
		}
	}
	return fmt.Errorf("patchSecretKey %s/%s: exceeded %d retries on conflict", secretName, key, maxRetries)
}

// UpsertSecret creates or updates a Kubernetes Secret.
func UpsertSecret(ctx context.Context, k8s kubernetes.Interface, secret *corev1.Secret) error {
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
// A no-op when deployment is empty (e.g. FreeRADIUS is disabled).
func Reload(ctx context.Context, k8s kubernetes.Interface, namespace, deployment string) error {
	if deployment == "" {
		return nil
	}
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().Format(time.RFC3339),
	)
	_, err := k8s.AppsV1().Deployments(namespace).Patch(
		ctx, deployment, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	return err
}
