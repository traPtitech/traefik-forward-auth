package tfa

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/traPtitech/traefik-forward-auth/internal/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traPtitech/traefik-forward-auth/internal/provider"
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

func TestAuthValidateRedirect(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	newRedirectRequest := func(urlStr string) *http.Request {
		u, err := url.Parse(urlStr)
		assert.Nil(err)

		r, _ := http.NewRequest("GET", urlStr, nil)
		r.Header.Add("X-Forwarded-Proto", u.Scheme)
		r.Header.Add("X-Forwarded-Host", u.Host)
		r.Header.Add("X-Forwarded-Uri", u.RequestURI())

		return r
	}

	errStr := "redirect host does not match request host (must match when not using auth host)"

	_, err := ValidateRedirect(
		newRedirectRequest("http://app.example.com/_oauth?state=123"),
		"http://app.example.com.bad.com",
	)
	if assert.Error(err) {
		assert.Equal(errStr, err.Error(), "Should not allow redirect to subdomain")
	}

	_, err = ValidateRedirect(
		newRedirectRequest("http://app.example.com/_oauth?state=123"),
		"http://app.example.combad.com",
	)
	if assert.Error(err) {
		assert.Equal(errStr, err.Error(), "Should not allow redirect to overlapping domain")
	}

	_, err = ValidateRedirect(
		newRedirectRequest("http://app.example.com/_oauth?state=123"),
		"http://example.com",
	)
	if assert.Error(err) {
		assert.Equal(errStr, err.Error(), "Should not allow redirect from subdomain")
	}

	_, err = ValidateRedirect(
		newRedirectRequest("http://app.example.com/_oauth?state=123"),
		"http://app.example.com/profile",
	)
	assert.Nil(err, "Should allow same domain")

	//
	// With Auth Host
	//
	config.AuthHost = []string{"auth.example.com"}
	config.CookieDomains = []CookieDomain{"example.com"}
	errStr = "redirect host does not match any expected hosts (should match cookie domain when using auth host)"

	_, err = ValidateRedirect(
		newRedirectRequest("http://app.example.com/_oauth?state=123"),
		"http://app.example.com.bad.com",
	)
	if assert.Error(err) {
		assert.Equal(errStr, err.Error(), "Should not allow redirect to subdomain")
	}

	_, err = ValidateRedirect(
		newRedirectRequest("http://app.example.com/_oauth?state=123"),
		"http://app.example.combad.com",
	)
	if assert.Error(err) {
		assert.Equal(errStr, err.Error(), "Should not allow redirect to overlapping domain")
	}

	_, err = ValidateRedirect(
		newRedirectRequest("http://auth.example.com/_oauth?state=123"),
		"http://app.example.com/profile",
	)
	assert.Nil(err, "Should allow between subdomains when using auth host")

	_, err = ValidateRedirect(
		newRedirectRequest("http://auth.example.com/_oauth?state=123"),
		"http://auth.example.com/profile",
	)
	assert.Nil(err, "Should allow same domain when using auth host")

	_, err = ValidateRedirect(
		newRedirectRequest("http://auth.example.com/_oauth?state=123"),
		"http://example.com/profile",
	)
	assert.Nil(err, "Should allow from subdomain when using auth host")
}

func TestRedirectUri(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	r := httptest.NewRequest("GET", "http://app.example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "http")

	//
	// No Auth Host
	//
	uri, err := url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("app.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With Auth URL but no matching cookie domain
	// - will not use auth host
	//
	config.AuthHost = []string{"auth.example.com"}

	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("app.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With correct Auth URL + cookie domain
	//
	config.AuthHost = []string{"auth.example.com"}
	config.CookieDomains = []CookieDomain{"example.com"}

	// Check url
	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("auth.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With Auth URL + cookie domain, but from different domain
	// - will not use auth host
	//
	r = httptest.NewRequest("GET", "https://another.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "https")

	config.AuthHost = []string{"auth.example.com"}
	config.CookieDomains = []CookieDomain{"example.com"}

	// Check url
	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("another.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)
}

func TestAuthMakeCookie(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	c, err := MakeCookie(r, "test@example.com")
	assert.NoError(err)
	assert.Equal("_forward_auth", c.Name)
	parts := strings.Split(c.Value, ".")
	assert.Len(parts, 3, "cookie should be 3 parts")
	_, err = token.VerifyToken(c.Value, config.secretBytes)
	assert.Nil(err, "should generate valid cookie")
	assert.Equal("/", c.Path)
	assert.Equal("app.example.com", c.Domain)
	assert.True(c.Secure)

	expires := time.Now().Local().Add(config.lifetimeDuration)
	assert.WithinDuration(expires, c.Expires, 10*time.Second)

	config.CookieName = "testname"
	config.InsecureCookie = true
	c, err = MakeCookie(r, "test@example.com")
	assert.NoError(err)
	assert.Equal("testname", c.Name)
	assert.False(c.Secure)
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	// No cookie domain or auth url
	c := MakeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("_forward_auth_csrf_123456", c.Name)
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain but no auth url
	config.CookieDomains = []CookieDomain{"example.com"}
	c = MakeCSRFCookie(r, "12222278901234567890123456789012")
	assert.Equal("_forward_auth_csrf_122222", c.Name)
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain and auth url
	config.AuthHost = []string{"auth.example.com"}
	config.CookieDomains = []CookieDomain{"example.com"}
	c = MakeCSRFCookie(r, "12333378901234567890123456789012")
	assert.Equal("_forward_auth_csrf_123333", c.Name)
	assert.Equal("example.com", c.Domain)
}

func TestAuthClearCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	r, _ := http.NewRequest("GET", "http://example.com", nil)

	c := ClearCSRFCookie(r, &http.Cookie{Name: "someCsrfCookie"})
	assert.Equal("someCsrfCookie", c.Name)
	if c.Value != "" {
		t.Error("ClearCSRFCookie should create cookie with empty value")
	}
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	c := &http.Cookie{}
	state := ""

	// Should require 32 char string
	state = ""
	c.Value = ""
	valid, _, _, err := ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("invalid CSRF cookie value", err.Error())
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, _, err = ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("invalid CSRF cookie value", err.Error())
	}

	// Should require provider
	state = "12345678901234567890123456789012:99"
	c.Value = "12345678901234567890123456789012"
	valid, _, _, err = ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("invalid CSRF state format", err.Error())
	}

	// Should allow valid state
	state = "12345678901234567890123456789012:p99:url123"
	c.Value = "12345678901234567890123456789012"
	valid, provider, redirect, err := ValidateCSRFCookie(c, state)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("p99", provider, "valid request should return correct provider")
	assert.Equal("url123", redirect, "valid request should return correct redirect")
}

func TestValidateState(t *testing.T) {
	assert := assert.New(t)

	// Should require valid state
	state := "12345678901234567890123456789012:"
	err := ValidateState(state)
	if assert.Error(err) {
		assert.Equal("invalid CSRF state value", err.Error())
	}
	// Should pass this state
	state = "12345678901234567890123456789012:p99:url123"
	err = ValidateState(state)
	assert.Nil(err, "valid request should not return an error")
}

func TestMakeState(t *testing.T) {
	assert := assert.New(t)

	redirect := "http://example.com/hello"

	// Test with google
	p := provider.Google{}
	state := MakeState(redirect, &p, "nonce")
	assert.Equal("nonce:google:http://example.com/hello", state)

	// Test with OIDC
	p2 := provider.OIDC{}
	state = MakeState(redirect, &p2, "nonce")
	assert.Equal("nonce:oidc:http://example.com/hello", state)

	// Test with Generic OAuth
	p3 := provider.GenericOAuth{}
	state = MakeState(redirect, &p3, "nonce")
	assert.Equal("nonce:generic-oauth:http://example.com/hello", state)
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

func TestAuthCookieDomainMatch(t *testing.T) {
	assert := assert.New(t)
	cd := "example.com"

	// Exact should match
	assert.True(CookieDomainMatch(cd, "example.com"), "exact domain should match")

	// Subdomain should match
	assert.True(CookieDomainMatch(cd, "test.example.com"), "subdomain should match")
	assert.True(CookieDomainMatch(cd, "twolevels.test.example.com"), "subdomain should match")
	assert.True(CookieDomainMatch(cd, "many.many.levels.test.example.com"), "subdomain should match")

	// Derived domain should not match
	assert.False(CookieDomainMatch(cd, "testexample.com"), "derived domain should not match")

	// Other domain should not match
	assert.False(CookieDomainMatch(cd, "test.com"), "other domain should not match")
}
