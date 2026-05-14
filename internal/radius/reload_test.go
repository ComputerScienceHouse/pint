// internal/radius/reload_test.go
package radius_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/radius"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newConfigSecret(ns, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data: map[string][]byte{
			"clients.json":   []byte("[]"),
			"clients.conf":   []byte(""),
			"status-secret":  []byte(""),
			"status":         []byte(""),
			"radsec-tls.conf": []byte(""),
		},
	}
}

func TestWriteRadiusConfig(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset(newConfigSecret("default", "pint-config"))

	clients := []radius.RadiusClient{
		{Username: "mbillow", IPCIDR: nil},
	}

	if err := radius.WriteRadiusConfig(ctx, k8s, "default", "pint-config", clients); err != nil {
		t.Fatalf("WriteRadiusConfig() error: %v", err)
	}

	secret, err := k8s.CoreV1().Secrets("default").Get(ctx, "pint-config", metav1.GetOptions{})
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
	wifiCAPEM := []byte("-----BEGIN CERTIFICATE-----\nfake-wifi-ca\n-----END CERTIFICATE-----\n")

	if err := radius.WriteRadSecServerCert(ctx, k8s, "default", "pint-radsec-server", certPEM, keyPEM, caPEM, wifiCAPEM); err != nil {
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
	if string(secret.Data["wifi-ca.pem"]) != string(wifiCAPEM) {
		t.Error("wifi-ca.pem does not match")
	}

	// Call again to exercise the update path
	if err := radius.WriteRadSecServerCert(ctx, k8s, "default", "pint-radsec-server", certPEM, keyPEM, caPEM, wifiCAPEM); err != nil {
		t.Fatalf("WriteRadSecServerCert() update error: %v", err)
	}
}

func TestWriteRadSecTLS_WritesAndDetectsChanges(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset(newConfigSecret("default", "pint-config"))

	updated, err := radius.WriteRadSecTLS(ctx, k8s, "default", "pint-config", false)
	if err != nil {
		t.Fatalf("WriteRadSecTLS() error: %v", err)
	}
	if !updated {
		t.Error("expected updated=true on first write")
	}

	secret, err := k8s.CoreV1().Secrets("default").Get(ctx, "pint-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get secret error: %v", err)
	}
	if !strings.Contains(string(secret.Data["radsec-tls.conf"]), "check_crl      = no") {
		t.Error("expected check_crl = no in radsec-tls.conf")
	}

	// Second write with same value should not report updated.
	updated, err = radius.WriteRadSecTLS(ctx, k8s, "default", "pint-config", false)
	if err != nil {
		t.Fatalf("WriteRadSecTLS() second call error: %v", err)
	}
	if updated {
		t.Error("expected updated=false when config unchanged")
	}
}

func TestReload_DeploymentNotFound(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()

	if err := radius.Reload(ctx, k8s, "default", "pint-freeradius"); err == nil {
		t.Fatal("expected error when deployment not found")
	}
}

func TestReload_PatchesDeployment(t *testing.T) {
	ctx := context.Background()
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "pint-freeradius", Namespace: "default"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{},
			Template: corev1.PodTemplateSpec{},
		},
	}
	k8s := fake.NewSimpleClientset(deploy)

	if err := radius.Reload(ctx, k8s, "default", "pint-freeradius"); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	updated, err := k8s.AppsV1().Deployments("default").Get(ctx, "pint-freeradius", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get deployment error: %v", err)
	}
	if updated.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] == "" {
		t.Error("restartedAt annotation not set on pod template")
	}
}
