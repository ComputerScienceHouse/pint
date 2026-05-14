// internal/radius/reload_test.go
package radius_test

import (
	"context"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/radius"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestWriteRadiusConfig(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()

	clients := []radius.RadiusClient{
		{Username: "mbillow", IPCIDR: nil},
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
	wifiCAPEM := []byte("-----BEGIN CERTIFICATE-----\nfake-wifi-ca\n-----END CERTIFICATE-----\n")

	err := radius.WriteRadSecServerCert(ctx, k8s, "default", "pint-radsec-server", certPEM, keyPEM, caPEM, wifiCAPEM)
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
	if string(secret.Data["wifi-ca.pem"]) != string(wifiCAPEM) {
		t.Error("wifi-ca.pem does not match")
	}

	// Call again to exercise the update path
	err = radius.WriteRadSecServerCert(ctx, k8s, "default", "pint-radsec-server", certPEM, keyPEM, caPEM, wifiCAPEM)
	if err != nil {
		t.Fatalf("WriteRadSecServerCert() update error: %v", err)
	}
}

func TestReload_DeploymentNotFound(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()

	err := radius.Reload(ctx, k8s, "default", "pint-freeradius")
	if err == nil {
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
