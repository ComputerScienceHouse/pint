// internal/radius/reload.go
package radius

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
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

// upsertSecret creates or updates a Kubernetes Secret.
func upsertSecret(ctx context.Context, k8s kubernetes.Interface, secret *corev1.Secret) error {
	ns := secret.Namespace
	_, err := k8s.CoreV1().Secrets(ns).Update(ctx, secret, metav1.UpdateOptions{})
	if errors.IsNotFound(err) {
		_, err = k8s.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{})
	}
	return err
}

// Reload finds the first FreeRADIUS pod matching podSelector and sends SIGHUP (kill -HUP 1).
func Reload(ctx context.Context, k8s kubernetes.Interface, restCfg *rest.Config, namespace, podSelector string) error {
	pods, err := k8s.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: podSelector,
	})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return fmt.Errorf("no FreeRADIUS pod found matching %s", podSelector)
	}
	pod := pods.Items[0]

	restClient := k8s.CoreV1().RESTClient()
	if restClient == nil {
		return fmt.Errorf("REST client is not available")
	}

	req := restClient.Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"kill", "-HUP", "1"},
			Stdout:  true,
			Stderr:  true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restCfg, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
}
