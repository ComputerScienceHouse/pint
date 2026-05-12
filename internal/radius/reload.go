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

// WriteRadiusConfig renders clients.conf from the given client list and writes it
// to the named Kubernetes Secret (creating it if needed).
func WriteRadiusConfig(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string, clients []RadiusClient) error {
	conf := RenderClientsConf(clients)
	return upsertSecret(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data:       map[string][]byte{"clients.conf": []byte(conf)},
	})
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

// EnsureConfigSecrets creates the RADIUS client secrets with empty content if they don't
// already exist. Safe to call on every startup — it is a no-op when secrets are present.
func EnsureConfigSecrets(ctx context.Context, k8s kubernetes.Interface, namespace, clientsSecret, configSecret string) error {
	if err := createIfAbsent(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: clientsSecret, Namespace: namespace},
		Data:       map[string][]byte{"clients.json": []byte("[]")},
	}); err != nil {
		return fmt.Errorf("init clients secret: %w", err)
	}
	if err := createIfAbsent(ctx, k8s, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: configSecret, Namespace: namespace},
		Data:       map[string][]byte{"clients.conf": []byte(RenderClientsConf(nil))},
	}); err != nil {
		return fmt.Errorf("init config secret: %w", err)
	}
	return nil
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
