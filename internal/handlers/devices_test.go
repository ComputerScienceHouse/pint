// internal/handlers/devices_test.go
package handlers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/devicemap"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/handlers"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"k8s.io/client-go/kubernetes/fake"
)

// mockIPA implements handlers.FreeIPAClient for tests.
type mockIPA struct {
	certs         []freeipa.CertInfo
	certFindErr   error
	certRevokeErr error
	revokeCount   int
}

func (m *mockIPA) CertFind(_, _ string) ([]freeipa.CertInfo, error) {
	return m.certs, m.certFindErr
}

func (m *mockIPA) CertRevoke(_ int64, _ string, _ int) error {
	m.revokeCount++
	return m.certRevokeErr
}

func (m *mockIPA) CertRequest(_, _, _, _ string) ([]byte, error) { return nil, nil }

func newDeviceServer(ipa *mockIPA) (*handlers.Server, *devicemap.DeviceMap) {
	dm := devicemap.New(fake.NewSimpleClientset(), "default", "pint-devices")
	return &handlers.Server{
		Cfg: &config.Config{IPAWirelessCAName: "ipa"},
		IPA: ipa,
		DM:  dm,
	}, dm
}

func newDeviceRouter(username string, s *handlers.Server, method, path string, h gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(sessions.Sessions("pint_session", cookie.NewStore([]byte("test"))))
	r.Handle(method, path, testAuth(username), h)
	return r
}

func postForm(t *testing.T, r *gin.Engine, path string, vals url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func assertRedirect(t *testing.T, w *httptest.ResponseRecorder, loc string) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != loc {
		t.Errorf("Location = %q, want %q", got, loc)
	}
}

func TestRevokeDevice(t *testing.T) {
	const (
		username  = "alice"
		serialStr = "42"
		serial    = int64(42)
	)

	owned := []freeipa.CertInfo{{SerialNumber: serial, ValidNotAfter: "99991231235959Z"}}

	tests := []struct {
		name            string
		serial          string
		ipa             *mockIPA
		wantRevokeCall  bool
	}{
		{
			name:   "empty serial",
			serial: "",
			ipa:    &mockIPA{certs: owned},
		},
		{
			name:   "cert_find error",
			serial: serialStr,
			ipa:    &mockIPA{certFindErr: errors.New("ipa down")},
		},
		{
			name:   "cert not owned",
			serial: serialStr,
			ipa:    &mockIPA{certs: []freeipa.CertInfo{{SerialNumber: 999}}},
		},
		{
			name:           "revoke error",
			serial:         serialStr,
			ipa:            &mockIPA{certs: owned, certRevokeErr: errors.New("revoke failed")},
			wantRevokeCall: true,
		},
		{
			name:           "success",
			serial:         serialStr,
			ipa:            &mockIPA{certs: owned},
			wantRevokeCall: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newDeviceServer(tc.ipa)
			r := newDeviceRouter(username, s, http.MethodPost, "/devices/revoke", s.RevokeDevice)

			w := postForm(t, r, "/devices/revoke", url.Values{"serial": {tc.serial}})

			assertRedirect(t, w, "/devices")
			if got := tc.ipa.revokeCount > 0; got != tc.wantRevokeCall {
				t.Errorf("CertRevoke called = %v, want %v", got, tc.wantRevokeCall)
			}
		})
	}
}

func TestEditDevice(t *testing.T) {
	const (
		username  = "alice"
		serialStr = "42"
		serial    = int64(42)
	)

	owned := []freeipa.CertInfo{{SerialNumber: serial, ValidNotAfter: "99991231235959Z"}}

	existingEntry := devicemap.DeviceInfo{
		Username:   username,
		DeviceName: "Old name",
		Platform:   "ios",
		EnrolledAt: time.Now(),
	}

	tests := []struct {
		name       string
		serial     string
		deviceName string
		platform   string
		ipa        *mockIPA
		setupDM    func(context.Context, *devicemap.DeviceMap)
		wantName   string
		wantPlatform string
	}{
		{
			name:     "empty serial",
			serial:   "",
			platform: "ios",
			ipa:      &mockIPA{certs: owned},
		},
		{
			name:       "name too long",
			serial:     serialStr,
			deviceName: strings.Repeat("a", 65),
			platform:   "ios",
			ipa:        &mockIPA{certs: owned},
		},
		{
			name:       "invalid platform",
			serial:     serialStr,
			deviceName: "My Device",
			platform:   "beos",
			ipa:        &mockIPA{certs: owned},
		},
		{
			name:       "non-numeric serial",
			serial:     "not-a-number",
			deviceName: "My Device",
			platform:   "linux",
			ipa:        &mockIPA{certs: owned},
		},
		{
			name:       "cert_find error",
			serial:     serialStr,
			deviceName: "My Device",
			platform:   "linux",
			ipa:        &mockIPA{certFindErr: errors.New("ipa down")},
		},
		{
			name:       "cert not owned",
			serial:     serialStr,
			deviceName: "My Device",
			platform:   "linux",
			ipa:        &mockIPA{certs: []freeipa.CertInfo{{SerialNumber: 999}}},
		},
		{
			name:       "map owner mismatch",
			serial:     serialStr,
			deviceName: "My Device",
			platform:   "linux",
			ipa:        &mockIPA{certs: owned},
			setupDM: func(ctx context.Context, dm *devicemap.DeviceMap) {
				_ = dm.Set(ctx, serialStr, devicemap.DeviceInfo{Username: "eve", Platform: "ios"})
			},
		},
		{
			name:         "success update existing entry",
			serial:       serialStr,
			deviceName:   "New Name",
			platform:     "android",
			ipa:          &mockIPA{certs: owned},
			setupDM: func(ctx context.Context, dm *devicemap.DeviceMap) {
				_ = dm.Set(ctx, serialStr, existingEntry)
			},
			wantName:     "New Name",
			wantPlatform: "android",
		},
		{
			name:         "success create entry for unknown device",
			serial:       serialStr,
			deviceName:   "New Laptop",
			platform:     "linux",
			ipa:          &mockIPA{certs: owned},
			wantName:     "New Laptop",
			wantPlatform: "linux",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, dm := newDeviceServer(tc.ipa)
			ctx := context.Background()
			if tc.setupDM != nil {
				tc.setupDM(ctx, dm)
			}

			r := newDeviceRouter(username, s, http.MethodPost, "/devices/edit", s.EditDevice)
			w := postForm(t, r, "/devices/edit", url.Values{
				"serial":      {tc.serial},
				"device_name": {tc.deviceName},
				"platform":    {tc.platform},
			})

			assertRedirect(t, w, "/devices")

			if tc.wantName != "" || tc.wantPlatform != "" {
				info, ok, err := dm.Get(ctx, serialStr)
				if err != nil {
					t.Fatalf("dm.Get: %v", err)
				}
				if !ok {
					t.Fatal("expected device map entry to exist after successful edit")
				}
				if info.DeviceName != tc.wantName {
					t.Errorf("DeviceName = %q, want %q", info.DeviceName, tc.wantName)
				}
				if info.Platform != tc.wantPlatform {
					t.Errorf("Platform = %q, want %q", info.Platform, tc.wantPlatform)
				}
				if info.Username != username {
					t.Errorf("Username = %q, want %q", info.Username, username)
				}
			}
		})
	}
}
