package activedirectory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		desc      string
		config    dynamic.ActiveDirectoryAuth
		expectErr bool
	}{
		{
			desc: "valid configuration",
			config: dynamic.ActiveDirectoryAuth{
				ServerURL: "http://entserver:8080",
				EonID:     "eon123",
				Env:       "dev",
				Action:    "read",
			},
			expectErr: false,
		},
		{
			desc: "missing server URL",
			config: dynamic.ActiveDirectoryAuth{
				EonID:  "eon123",
				Env:    "dev",
				Action: "read",
			},
			expectErr: true,
		},
		{
			desc: "missing eon ID",
			config: dynamic.ActiveDirectoryAuth{
				ServerURL: "http://entserver:8080",
				Env:       "dev",
				Action:    "read",
			},
			expectErr: true,
		},
		{
			desc: "missing env",
			config: dynamic.ActiveDirectoryAuth{
				ServerURL: "http://entserver:8080",
				EonID:     "eon123",
				Action:    "read",
			},
			expectErr: true,
		},
		{
			desc: "missing action",
			config: dynamic.ActiveDirectoryAuth{
				ServerURL: "http://entserver:8080",
				EonID:     "eon123",
				Env:       "dev",
			},
			expectErr: true,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			_, err := New(context.Background(), next, test.config, "test")

			if test.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestActiveDirectoryAuth_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc           string
		userIDHeader   string
		userIDValue    string
		serverResponse EntitlementResponse
		serverStatus   int
		expectStatus   int
		expectUserID   string
	}{
		{
			desc:         "authorized user",
			userIDHeader: "X-User-ID",
			userIDValue:  "testuser",
			serverResponse: EntitlementResponse{
				Entitled: true,
			},
			serverStatus: http.StatusOK,
			expectStatus: http.StatusOK,
			expectUserID: "testuser",
		},
		{
			desc:         "unauthorized user",
			userIDHeader: "X-User-ID",
			userIDValue:  "testuser",
			serverResponse: EntitlementResponse{
				Entitled: false,
				Message:  "Access denied",
			},
			serverStatus: http.StatusOK,
			expectStatus: http.StatusForbidden,
		},
		{
			desc:         "missing user ID header",
			userIDHeader: "X-User-ID",
			userIDValue:  "",
			expectStatus: http.StatusUnauthorized,
		},
		{
			desc:         "server error",
			userIDHeader: "X-User-ID",
			userIDValue:  "testuser",
			serverStatus: http.StatusInternalServerError,
			expectStatus: http.StatusInternalServerError,
		},
		{
			desc:         "user with domain prefix",
			userIDHeader: "X-User-ID",
			userIDValue:  "DOMAIN\\testuser",
			serverResponse: EntitlementResponse{
				Entitled: true,
			},
			serverStatus: http.StatusOK,
			expectStatus: http.StatusOK,
			expectUserID: "testuser",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			// Create mock entitlement server
			var receivedRequest EntitlementRequest
			entServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.serverStatus == 0 {
					test.serverStatus = http.StatusOK
				}

				// Parse request
				err := json.NewDecoder(r.Body).Decode(&receivedRequest)
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.serverStatus)

				if test.serverStatus == http.StatusOK {
					json.NewEncoder(w).Encode(test.serverResponse)
				}
			}))
			defer entServer.Close()

			// Create middleware
			config := dynamic.ActiveDirectoryAuth{
				ServerURL:    entServer.URL,
				EonID:        "eon123",
				Env:          "dev",
				Action:       "read",
				UserIDHeader: test.userIDHeader,
				Timeout:      1 * time.Second,
			}

			called := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				called = true
				rw.WriteHeader(http.StatusOK)
			})

			middleware, err := New(context.Background(), next, config, "test")
			require.NoError(t, err)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if test.userIDValue != "" {
				req.Header.Set(test.userIDHeader, test.userIDValue)
			}

			rr := httptest.NewRecorder()

			// Execute request
			middleware.ServeHTTP(rr, req)

			// Check response status
			assert.Equal(t, test.expectStatus, rr.Code)

			// If authorized, check that next handler was called
			if test.expectStatus == http.StatusOK {
				assert.True(t, called, "next handler should be called for authorized requests")

				// Check that the entitlement server received the correct request
				assert.Equal(t, test.expectUserID, receivedRequest.UserID)
				assert.Equal(t, "eon123", receivedRequest.EonID)
				assert.Equal(t, "dev", receivedRequest.Env)
				assert.Equal(t, "read", receivedRequest.Action)
			} else {
				assert.False(t, called, "next handler should not be called for unauthorized requests")
			}
		})
	}
}

func TestActiveDirectoryAuth_checkEntitlement(t *testing.T) {
	testCases := []struct {
		desc           string
		userID         string
		serverResponse EntitlementResponse
		serverStatus   int
		expectEntitled bool
		expectError    bool
	}{
		{
			desc:   "user entitled",
			userID: "testuser",
			serverResponse: EntitlementResponse{
				Entitled: true,
			},
			serverStatus:   http.StatusOK,
			expectEntitled: true,
			expectError:    false,
		},
		{
			desc:   "user not entitled",
			userID: "testuser",
			serverResponse: EntitlementResponse{
				Entitled: false,
				Message:  "Access denied",
			},
			serverStatus:   http.StatusOK,
			expectEntitled: false,
			expectError:    false,
		},
		{
			desc:           "server error",
			userID:         "testuser",
			serverStatus:   http.StatusInternalServerError,
			expectEntitled: false,
			expectError:    true,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.serverStatus)

				if test.serverStatus == http.StatusOK {
					json.NewEncoder(w).Encode(test.serverResponse)
				}
			}))
			defer server.Close()

			// Create middleware instance
			config := dynamic.ActiveDirectoryAuth{
				ServerURL: server.URL,
				EonID:     "eon123",
				Env:       "dev",
				Action:    "read",
				Timeout:   1 * time.Second,
			}

			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			middleware, err := New(context.Background(), next, config, "test")
			require.NoError(t, err)

			adAuth := middleware.(*activeDirectoryAuth)

			// Test entitlement check
			entitled, err := adAuth.checkEntitlement(context.Background(), test.userID)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectEntitled, entitled)
			}
		})
	}
}

func TestActiveDirectoryAuth_RemoveHeader(t *testing.T) {
	// Create mock entitlement server that always authorizes
	entServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EntitlementResponse{Entitled: true})
	}))
	defer entServer.Close()

	config := dynamic.ActiveDirectoryAuth{
		ServerURL:    entServer.URL,
		EonID:        "eon123",
		Env:          "dev",
		Action:       "read",
		UserIDHeader: "X-User-ID",
		RemoveHeader: true,
		Timeout:      1 * time.Second,
	}

	var headerValue string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		headerValue = req.Header.Get("X-User-ID")
		rw.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-User-ID", "testuser")

	rr := httptest.NewRecorder()
	middleware.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, headerValue, "header should be removed when RemoveHeader is true")
}

func TestActiveDirectoryAuth_Timeout(t *testing.T) {
	// Create server that delays response
	entServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Delay longer than timeout
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EntitlementResponse{Entitled: true})
	}))
	defer entServer.Close()

	config := dynamic.ActiveDirectoryAuth{
		ServerURL:    entServer.URL,
		EonID:        "eon123",
		Env:          "dev",
		Action:       "read",
		UserIDHeader: "X-User-ID",
		Timeout:      100 * time.Millisecond, // Short timeout
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-User-ID", "testuser")

	rr := httptest.NewRecorder()
	middleware.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestActiveDirectoryAuth_DefaultValues(t *testing.T) {
	config := dynamic.ActiveDirectoryAuth{
		ServerURL: "http://entserver:8080",
		EonID:     "eon123",
		Env:       "dev",
		Action:    "read",
		// UserIDHeader and Timeout not specified, should use defaults
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	middleware, err := New(context.Background(), next, config, "test")
	require.NoError(t, err)

	adAuth := middleware.(*activeDirectoryAuth)

	assert.Equal(t, "X-User-ID", adAuth.userIDHeader, "should use default UserIDHeader")
	assert.Equal(t, 5*time.Second, adAuth.timeoutDuration, "should use default timeout")
}

func TestEntitlementRequest_JSON(t *testing.T) {
	req := EntitlementRequest{
		UserID: "testuser",
		EonID:  "eon123",
		Env:    "dev",
		Action: "read",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	expected := `{"userID":"testuser","eonID":"eon123","env":"dev","action":"read"}`
	assert.JSONEq(t, expected, string(data))
}

func TestEntitlementResponse_JSON(t *testing.T) {
	resp := EntitlementResponse{
		Entitled: true,
		Message:  "Access granted",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	expected := `{"entitled":true,"message":"Access granted"}`
	assert.JSONEq(t, expected, string(data))
}
