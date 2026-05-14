// internal/radius/store_test.go
package radius_test

import (
	"context"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/radius"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestStore_UpsertAndLoad(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()

	store := radius.NewClientStore(k8s, "default", "pint-radius-clients")

	if err := store.Load(ctx); err != nil {
		t.Fatalf("Load on missing secret should not error: %v", err)
	}

	ipCIDR := "192.168.1.0/24"
	store.Upsert(radius.RadiusClient{Username: "mbillow", IPCIDR: &ipCIDR})

	if err := store.Save(ctx); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load fresh store from same k8s client
	store2 := radius.NewClientStore(k8s, "default", "pint-radius-clients")
	if err := store2.Load(ctx); err != nil {
		t.Fatalf("Load() after Save() error: %v", err)
	}
	c := store2.FindByUsername("mbillow")
	if c == nil {
		t.Fatal("FindByUsername returned nil")
	}
	if c.IPCIDR == nil || *c.IPCIDR != "192.168.1.0/24" {
		t.Errorf("IPCIDR = %v, want 192.168.1.0/24", c.IPCIDR)
	}
}

func TestStore_UpsertOverwrites(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()
	store := radius.NewClientStore(k8s, "default", "pint-radius-clients")
	if err := store.Load(ctx); err != nil {
		t.Fatal(err)
	}

	ip1 := "10.0.0.1"
	ip2 := "10.0.0.2"
	store.Upsert(radius.RadiusClient{Username: "mbillow", IPCIDR: &ip1})
	store.Upsert(radius.RadiusClient{Username: "mbillow", IPCIDR: &ip2})

	c := store.FindByUsername("mbillow")
	if c.IPCIDR == nil || *c.IPCIDR != ip2 {
		t.Errorf("IPCIDR = %v, want %q", c.IPCIDR, ip2)
	}
	if store.Len() != 1 {
		t.Errorf("Len() = %d, want 1", store.Len())
	}
}

func TestStore_Delete(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewSimpleClientset()
	store := radius.NewClientStore(k8s, "default", "pint-radius-clients")
	if err := store.Load(ctx); err != nil {
		t.Fatal(err)
	}

	store.Upsert(radius.RadiusClient{Username: "mbillow"})
	store.Delete("mbillow")

	if store.FindByUsername("mbillow") != nil {
		t.Error("FindByUsername should return nil after Delete")
	}
}

func TestStore_LoadExisting(t *testing.T) {
	ctx := context.Background()

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pint-radius-clients", Namespace: "default"},
		Data: map[string][]byte{
			// legacy JSON with "secret" field is silently ignored on load
			"clients.json": []byte(`[{"username":"jsmith","secret":"abc","ip_cidr":null}]`),
		},
	}
	k8s := fake.NewSimpleClientset(existing)
	store := radius.NewClientStore(k8s, "default", "pint-radius-clients")
	if err := store.Load(ctx); err != nil {
		t.Fatal(err)
	}
	c := store.FindByUsername("jsmith")
	if c == nil {
		t.Fatal("expected to find jsmith")
	}
	if c.IPCIDR != nil {
		t.Errorf("IPCIDR should be nil, got %v", c.IPCIDR)
	}
}
