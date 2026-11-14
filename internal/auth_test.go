package tfa

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/**
 * Tests
 */

func TestGetRedirectURI(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		headers map[string]string
		want    string
	}{
		{
			name: "no redirect param",
			path: "/",
			want: "/",
		},
		{
			name: "has redirect param",
			path: "/?redirect=/foo",
			want: "/foo",
		},
		{
			name: "has redirect param from forwarded uri header",
			path: "/",
			headers: map[string]string{
				"X-Forwarded-Uri": "/?redirect=/bar",
			},
			want: "/bar",
		},
	}
	for _, cc := range cases {
		t.Run(cc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", cc.path, nil)
			require.NoError(t, err)
			for k, v := range cc.headers {
				req.Header.Add(k, v)
			}
			got := GetRedirectURI(req)
			assert.Equal(t, cc.want, got)
		})
	}
}

func TestValidateRedirect(t *testing.T) {
	initTestConfig()
	config.AuthHost = []string{"auth.example.com"}
	config.AuthDomains = []AuthDomain{"example.com"}

	newRequest := func(host string) *http.Request {
		r := httptest.NewRequest("GET", "https://"+host+"/_oauth", nil)
		r.Host = host
		return r
	}

	sameHost := []struct {
		redirect string
		ok       bool
	}{
		{"https://app.example.com/profile", true},
		{"https://app.example.com.bad.com/", false},
		{"https://example.com/", false},
		{"javascript://app.example.com/", false},
		{"/relative", false},
	}
	for _, cc := range sameHost {
		_, err := validateSameHostRedirect(newRequest("app.example.com"), cc.redirect)
		assert.Equal(t, cc.ok, err == nil, "same host: %s", cc.redirect)
	}

	authHost := []struct {
		host     string
		redirect string
		ok       bool
	}{
		{"auth.example.com", "https://app.example.com/profile", true},
		{"auth.example.com", "https://example.com/", true},
		{"auth.example.com", "https://deep.app.example.com/", true},
		{"auth.example.com", "https://evilexample.com/", false},
		{"auth.example.com", "https://app.example.com.bad.com/", false},
		{"auth.example.com", "https://other.org/", false},
		{"auth.example.com", "ftp://app.example.com/", false},
		{"auth.example.com", "http://app.example.com/", false},
		{"auth.other.org", "https://auth.other.org/", false},
	}
	for _, cc := range authHost {
		_, err := validateAuthHostRedirect(newRequest(cc.host), cc.redirect)
		assert.Equal(t, cc.ok, err == nil, "auth host %s: %s", cc.host, cc.redirect)
	}
}

func TestAuthHostFor(t *testing.T) {
	initTestConfig()

	_, ok := authHostFor("app.example.com")
	assert.False(t, ok, "no auth host")

	config.AuthHost = []string{"auth.example.com"}
	config.AuthDomains = []AuthDomain{"example.com", "example.org"}
	authHost, ok := authHostFor("app.example.com")
	assert.True(t, ok)
	assert.Equal(t, "auth.example.com", authHost)

	_, ok = authHostFor("app.example.org")
	assert.False(t, ok, "host in an auth domain without an auth host")

	_, ok = authHostFor("another.com")
	assert.False(t, ok, "host outside auth domains")
}

func TestRedirectUri(t *testing.T) {
	initTestConfig()
	config.AuthHost = []string{"auth.example.com"}
	config.AuthDomains = []AuthDomain{"example.com"}

	r := httptest.NewRequest("GET", "http://app.example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "https")
	assert.Equal(t, "https://app.example.com/_oauth", redirectUri(r), "callback is on the receiving host")
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	initTestConfig()

	nonce := "12345678901234567890123456789012"
	c := MakeCSRFCookie(nonce)
	assert.Equal(t, "__Host-_forward_auth_csrf_"+hashNonce(nonce)[:6], c.Name)
	assert.Equal(t, nonce, c.Value)
	assert.Equal(t, "", c.Domain)
	assert.True(t, c.Secure)

	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.AddCookie(&http.Cookie{Name: c.Name, Value: "00000000000000000000000000000000"})
	r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	found, err := FindCSRFCookie(r, hashNonce(nonce))
	require.NoError(t, err)
	assert.Equal(t, nonce, found.Value)

	_, err = FindCSRFCookie(r, hashNonce("another"))
	assert.Error(t, err)

	cleared := ClearCSRFCookie(c)
	assert.Equal(t, c.Name, cleared.Name)
	assert.Equal(t, "", cleared.Value)
}

func TestAuthState(t *testing.T) {
	nonce := "12345678901234567890123456789012"
	state := authState{
		Nonce:        nonce,
		Provider:     "oidc",
		Probe:        true,
		AppNonceHash: hashNonce("app"),
		Redirect:     "https://app.example.com/path?a=b:c",
	}
	parsed, err := parseAuthState(state.String())
	require.NoError(t, err)
	assert.Equal(t, state, parsed)

	state = authState{Nonce: nonce, Provider: "google", Redirect: "https://app.example.com/"}
	parsed, err = parseAuthState(state.String())
	require.NoError(t, err)
	assert.Equal(t, state, parsed)

	for _, invalid := range []string{
		"",
		nonce + ":google:0::",
		"short:google:0::https://app.example.com/",
		nonce + ":google:2::https://app.example.com/",
		nonce + ":google:0:nothex:https://app.example.com/",
		nonce + ":google:https://app.example.com/",
	} {
		_, err := parseAuthState(invalid)
		assert.Error(t, err, invalid)
	}
}

func TestAuthNonce(t *testing.T) {
	assert := assert.New(t)
	err, nonce1 := Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce1, 32, "length should be 32 chars")

	err, nonce2 := Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce2, 32, "length should be 32 chars")

	assert.NotEqual(nonce1, nonce2, "nonce should not be equal")
}

func TestAuthDomainContains(t *testing.T) {
	assert := assert.New(t)
	d := AuthDomain("example.com")

	// Exact should match
	assert.True(d.Contains("example.com"), "exact domain should match")

	// Subdomain should match
	assert.True(d.Contains("test.example.com"), "subdomain should match")
	assert.True(d.Contains("twolevels.test.example.com"), "subdomain should match")
	assert.True(d.Contains("many.many.levels.test.example.com"), "subdomain should match")

	// Derived domain should not match
	assert.False(d.Contains("testexample.com"), "derived domain should not match")

	// Other domain should not match
	assert.False(d.Contains("test.com"), "other domain should not match")
}
