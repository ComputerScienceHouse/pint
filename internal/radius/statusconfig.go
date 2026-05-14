// internal/radius/statusconfig.go
package radius

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// EnsureStatusConfig ensures the status-secret key exists in the named Secret.
// If absent or empty, generates a random 32-char value and patches it in.
// Returns (secretValue, err).
func EnsureStatusConfig(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string) (string, error) {
	secret, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil {
		if data, ok := secret.Data[KeyStatusSecret]; ok && len(data) > 0 {
			return string(data), nil
		}
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate status secret: %w", err)
	}
	secretValue := hex.EncodeToString(b)

	if err := patchSecretKey(ctx, k8s, namespace, secretName, KeyStatusSecret, []byte(secretValue)); err != nil {
		return "", fmt.Errorf("patch status secret: %w", err)
	}
	return secretValue, nil
}

// RenderStatusConfig returns the FreeRADIUS client block for the status virtual server.
func RenderStatusConfig(secret, cidr string) string {
	return fmt.Sprintf(`client status {
    ipaddr = %s
    secret = %s
}`, cidr, secret)
}

// WriteStatusConfig patches the status key in the named Secret with the rendered config.
// Returns (didUpdate, err). didUpdate is false when the existing value is identical.
func WriteStatusConfig(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, config string) (bool, error) {
	existing, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil && string(existing.Data[KeyStatus]) == config {
		return false, nil
	}
	return true, patchSecretKey(ctx, k8s, namespace, secretName, KeyStatus, []byte(config))
}
