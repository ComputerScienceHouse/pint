// internal/radius/statusconfig.go
package radius

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const statusSecretName = "pint-freeradius-status-secret"

// EnsureStatusConfig ensures the FreeRADIUS status virtual server is configured.
// If the secret does not exist, it generates a random 32-char secret and creates it.
// Returns (secretValue, err).
func EnsureStatusConfig(ctx context.Context, k8s kubernetes.Interface, namespace string) (string, error) {
	secret, err := k8s.CoreV1().Secrets(namespace).Get(ctx, statusSecretName, metav1.GetOptions{})
	if err == nil {
		if data, ok := secret.Data["status-secret"]; ok {
			return string(data), nil
		}
	}

	// Generate new secret
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate status secret: %w", err)
	}
	secretValue := hex.EncodeToString(b)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statusSecretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"status-secret": []byte(secretValue),
		},
	}

	if _, err := k8s.CoreV1().Secrets(namespace).Create(ctx, newSecret, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("create status secret: %w", err)
	}

	return secretValue, nil
}

// RenderStatusConfig returns the FreeRADIUS virtual server configuration a la "clients.conf".
// This is intended to be included via $-INCLUDE into a virtual server block.
func RenderStatusConfig(port, secret, cidr string) string {
	return fmt.Sprintf(`client status {
    ipaddr = %s
    secret = %s
}`, cidr, secret)
}

// WriteStatusConfig writes the rendered status virtual server config to a K8S Secret.
// Returns (didUpdate, err). didUpdate is true if the secret was created or modified.
func WriteStatusConfig(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, config string) (bool, error) {
	data := map[string][]byte{
		"status": []byte(config),
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	existing, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil {
		// Check if existing data is identical to avoid unnecessary updates
		if string(existing.Data["status"]) == config {
			return false, nil
		}
	}

	_, err = k8s.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		// Create if not found
		_, err = k8s.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	}
	return true, err
}
