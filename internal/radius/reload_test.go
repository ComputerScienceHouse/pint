// internal/radius/reload_test.go
package radius_test

import (
	"context"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/radius"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestWriteRadiusConfig(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()

	clients := []radius.RadiusClient{
		{Username: "mbillow", Secret: "s3cr3t", IPCIDR: nil},
	}

	err := radius.WriteRadiusConfig(ctx, k8s, "default", "pint-radius-config", clients)
	if err != nil {
		t.Fatalf("WriteRadiusConfig() error: %v", err)
	}

	secret, err := k8s.CoreV1().Secrets("default").Get(ctx, "pint-radius-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get secret error: %v", err)
	}
	conf, ok := secret.Data["clients.conf"]
	if !ok {
		t.Fatal("clients.conf key missing from secret")
	}
	if len(conf) == 0 {
		t.Fatal("clients.conf is empty")
	}
}

func TestWriteRadSecServerCert(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()

	certPEM := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n")

	err := radius.WriteRadSecServerCert(ctx, k8s, "default", "pint-radsec-server", certPEM, keyPEM, caPEM)
	if err != nil {
		t.Fatalf("WriteRadSecServerCert() error: %v", err)
	}

	secret, err := k8s.CoreV1().Secrets("default").Get(ctx, "pint-radsec-server", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get secret error: %v", err)
	}
	if string(secret.Data["tls.crt"]) != string(certPEM) {
		t.Error("tls.crt does not match")
	}
	if string(secret.Data["tls.key"]) != string(keyPEM) {
		t.Error("tls.key does not match")
	}
	if string(secret.Data["ca.pem"]) != string(caPEM) {
		t.Error("ca.pem does not match")
	}

	// Call again to exercise the update path
	err = radius.WriteRadSecServerCert(ctx, k8s, "default", "pint-radsec-server", certPEM, keyPEM, caPEM)
	if err != nil {
		t.Fatalf("WriteRadSecServerCert() update error: %v", err)
	}
}

func TestReload_NoPodFound(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()
	restCfg := &rest.Config{Host: "https://fake"}

	err := radius.Reload(ctx, k8s, restCfg, "default", "app=freeradius")
	if err == nil {
		t.Fatal("expected error when no FreeRADIUS pod found")
	}
}

func TestReload_PodExists(t *testing.T) {
	// The fake clientset's RESTClient panics when building exec requests (nil
	// internal transport). Recover so we can still assert that Reload reached
	// the exec phase (i.e., it found the pod rather than returning early).
	podNotFound := false
	defer func() {
		if r := recover(); r != nil && podNotFound {
			t.Errorf("Reload returned pod-not-found instead of finding the pod: %v", r)
		}
	}()

	ctx := context.Background()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "freeradius-0",
			Namespace: "default",
			Labels:    map[string]string{"app": "freeradius"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	k8s := fake.NewSimpleClientset(pod)
	restCfg := &rest.Config{Host: "https://fake"}

	err := radius.Reload(ctx, k8s, restCfg, "default", "app=freeradius")
	if err != nil && err.Error() == "no FreeRADIUS pod found matching app=freeradius" {
		podNotFound = true
		t.Error("got pod-not-found error but pod was present")
	}
}
