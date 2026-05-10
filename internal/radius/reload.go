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
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data:       map[string][]byte{"clients.conf": []byte(conf)},
	}
	_, getErr := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	var err error
	if errors.IsNotFound(getErr) {
		_, err = k8s.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	} else {
		_, err = k8s.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	}
	return err
}

// WriteRadSecServerCert writes the FreeRADIUS TLS cert+key to the named K8s Secret.
// Called at startup; creates or updates the Secret.
func WriteRadSecServerCert(ctx context.Context, k8s kubernetes.Interface, namespace, secretName string, certPEM, keyPEM []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}
	_, getErr := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	var err error
	if errors.IsNotFound(getErr) {
		_, err = k8s.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	} else {
		_, err = k8s.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
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
