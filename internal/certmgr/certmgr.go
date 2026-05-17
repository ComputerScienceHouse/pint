// Package certmgr manages TLS certificate lifecycles backed by Kubernetes Secrets.
// A single Manager goroutine handles all registered certs with per-cert jitter so
// K8s API calls spread out, and it respects context cancellation for graceful shutdown.
package certmgr

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ManagedCert describes a TLS certificate whose lifecycle is owned by a Manager.
type ManagedCert interface {
	// Name returns a label used in log messages.
	Name() string
	// SecretRef returns the Kubernetes secret location and data key holding the cert PEM for expiry checks.
	SecretRef() (namespace, secretName, certKey string)
	// ShouldRenew inspects the existing cert PEM (nil if absent or unparseable) and returns true
	// when the cert must be (re-)issued. Implementations check expiry, required fields, and migration conditions.
	ShouldRenew(existingPEM []byte) bool
	// Issue provisions a new cert, stores it in Kubernetes, and returns the new leaf cert PEM.
	// existingPEM is the current value from SecretRef so implementations can handle migration
	// cases (e.g. appending a CA chain without re-issuing) without an extra K8s round-trip.
	Issue(ctx context.Context, existingPEM []byte) (certPEM []byte, err error)
	// AfterRenew is called after a successful Issue with the new leaf PEM, e.g. to hot-swap an
	// in-memory signer. Errors are logged but not propagated so a failed hook does not block renewal.
	AfterRenew(ctx context.Context, certPEM []byte) error
}

// Manager runs a single goroutine that checks all registered certs on a 24-hour ticker.
type Manager struct {
	log   *zap.Logger
	k8s   kubernetes.Interface
	certs []ManagedCert
}

// New creates a Manager. Call Register before RunOnce or Watch.
func New(log *zap.Logger, k8s kubernetes.Interface) *Manager {
	return &Manager{log: log, k8s: k8s}
}

func (m *Manager) Register(c ManagedCert) {
	m.certs = append(m.certs, c)
}

// RunOnce checks every registered cert and issues any that ShouldRenew.
// Returns all errors encountered joined together.
func (m *Manager) RunOnce(ctx context.Context) error {
	var errs []error
	for _, c := range m.certs {
		if err := m.checkAndRenew(ctx, c); err != nil {
			errs = append(errs, fmt.Errorf("certmgr %s: %w", c.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Watch loops forever, rechecking every cert every ~24 h with up to 30 min of per-cert
// jitter so K8s API bursts are spread across time. Stops when ctx is cancelled.
func (m *Manager) Watch(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, c := range m.certs {
				jitter := time.Duration(rand.Int63n(int64(30 * time.Minute))) //nolint:gosec
				select {
				case <-ctx.Done():
					return
				case <-time.After(jitter):
				}
				if err := m.checkAndRenew(ctx, c); err != nil {
					m.log.Error("cert renewal failed", zap.String("cert", c.Name()), zap.Error(err))
				}
			}
		}
	}
}

func (m *Manager) checkAndRenew(ctx context.Context, c ManagedCert) error {
	ns, secretName, certKey := c.SecretRef()

	var existingPEM []byte
	if secret, err := m.k8s.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{}); err == nil {
		existingPEM = secret.Data[certKey]
	}

	if !c.ShouldRenew(existingPEM) {
		m.log.Info("cert ok, no renewal needed", zap.String("cert", c.Name()))
		return nil
	}

	m.log.Info("issuing cert", zap.String("cert", c.Name()))
	certPEM, err := c.Issue(ctx, existingPEM)
	if err != nil {
		return err
	}
	m.log.Info("cert issued", zap.String("cert", c.Name()))

	if err := c.AfterRenew(ctx, certPEM); err != nil {
		m.log.Error("cert after-renew hook failed", zap.String("cert", c.Name()), zap.Error(err))
	}
	return nil
}
