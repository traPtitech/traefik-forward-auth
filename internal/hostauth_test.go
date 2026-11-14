package tfa

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traPtitech/traefik-forward-auth/internal/token"
)

func initAuthHostTestConfig(t *testing.T) {
	initTestConfig()
	config.AuthHost = []string{"auth.example.com"}
	config.AuthDomains = []AuthDomain{"example.com"}

	server, serverURL := NewOAuthServer(t)
	t.Cleanup(server.Close)
	config.Providers.Google.TokenURL = &url.URL{Scheme: serverURL.Scheme, Host: serverURL.Host, Path: "/token"}
	config.Providers.Google.UserURL = &url.URL{Scheme: serverURL.Scheme, Host: serverURL.Host, Path: "/userinfo"}
}

func newNavigationRequest(target string) *http.Request {
	r := newHTTPRequest("GET", target)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

func findResponseCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func findResponseCookieWithPrefix(res *http.Response, prefix string) *http.Cookie {
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	return nil
}

func doRequestWithCookies(r *http.Request, cookies ...*http.Cookie) *http.Response {
	for _, c := range cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	res, _ := doHttpRequest(r, nil)
	return res
}

func makeHostTokenCookie(t *testing.T, host string, user any) *http.Cookie {
	r := newHTTPRequest("GET", "https://"+host+"/")
	c, err := MakeCookie(r, user)
	require.NoError(t, err)
	return c
}

// loginFlow runs the login from an unauthenticated request on the app host
// up to the redirect to the ticket endpoint, and returns the app host's nonce cookie and the ticket URL.
func loginFlow(t *testing.T, appRequest *http.Request) (appNonce *http.Cookie, ticketURL *url.URL) {
	res := doRequestWithCookies(appRequest)
	require.Equal(t, 307, res.StatusCode)
	appNonce = findResponseCookieWithPrefix(res, "__Host-_forward_auth_csrf_")
	require.NotNil(t, appNonce)

	authorizeURL, err := res.Location()
	require.NoError(t, err)
	require.Equal(t, "auth.example.com", authorizeURL.Host)
	require.Equal(t, "/_oauth/authorize", authorizeURL.Path)

	res = doRequestWithCookies(newNavigationRequest(authorizeURL.String()))
	require.Equal(t, 307, res.StatusCode)
	authNonce := findResponseCookieWithPrefix(res, "__Host-_forward_auth_csrf_")
	require.NotNil(t, authNonce)
	providerURL, err := res.Location()
	require.NoError(t, err)
	state := providerURL.Query().Get("state")
	require.NotEmpty(t, state)

	callback := "https://auth.example.com/_oauth?" + url.Values{"code": {"code"}, "state": {state}}.Encode()
	res = doRequestWithCookies(newNavigationRequest(callback), authNonce)
	require.Equal(t, 307, res.StatusCode)
	ticketURL, err = res.Location()
	require.NoError(t, err)
	return appNonce, ticketURL
}

func TestHostTokenIsBoundToHost(t *testing.T) {
	initTestConfig()

	c := makeHostTokenCookie(t, "app.example.com", m{"email": "test@example.com"})

	res := doRequestWithCookies(newHTTPRequest("GET", "https://app.example.com/foo"), c)
	assert.Equal(t, 200, res.StatusCode, "host token should be accepted on its host")

	res = doRequestWithCookies(newHTTPRequest("GET", "https://other.example.com/foo"), c)
	assert.Equal(t, 307, res.StatusCode, "host token should not be accepted on another host")

	tk, err := token.SignTicket(token.Ticket{User: m{"email": "test@example.com"}, NonceHash: "x", Redirect: "https://app.example.com/"},
		"app.example.com", time.Now().Add(time.Minute), config.secretBytes)
	require.NoError(t, err)
	res = doRequestWithCookies(newHTTPRequest("GET", "https://app.example.com/foo"), &http.Cookie{Name: c.Name, Value: tk})
	assert.Equal(t, 307, res.StatusCode, "ticket should not be accepted as host token")
}

func TestHostTokenCookieAttributes(t *testing.T) {
	initTestConfig()

	c := makeHostTokenCookie(t, "app.example.com", m{"email": "test@example.com"})
	assert.Equal(t, "__Host-_forward_auth", c.Name)
	assert.Equal(t, "", c.Domain)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)

	config.InsecureCookie = true
	c = makeHostTokenCookie(t, "app.example.com", m{"email": "test@example.com"})
	assert.Equal(t, "_forward_auth", c.Name, "__Host- prefix requires Secure")
	assert.False(t, c.Secure)
}

func TestAuthHostLoginFlow(t *testing.T) {
	initAuthHostTestConfig(t)

	appNonce, ticketURL := loginFlow(t, newNavigationRequest("https://app.example.com/page?q=1"))
	assert.Equal(t, "app.example.com", ticketURL.Host)
	assert.Equal(t, "/_oauth/ticket", ticketURL.Path)

	t.Run("without nonce cookie", func(t *testing.T) {
		res := doRequestWithCookies(newNavigationRequest(ticketURL.String()))
		assert.Equal(t, 401, res.StatusCode)
	})

	t.Run("with another nonce cookie", func(t *testing.T) {
		other := &http.Cookie{Name: appNonce.Name, Value: strings.Repeat("0", 32)}
		res := doRequestWithCookies(newNavigationRequest(ticketURL.String()), other)
		assert.Equal(t, 401, res.StatusCode)
	})

	t.Run("on another host", func(t *testing.T) {
		u := *ticketURL
		u.Host = "evil.example.com"
		res := doRequestWithCookies(newNavigationRequest(u.String()), appNonce)
		assert.Equal(t, 401, res.StatusCode)
	})

	t.Run("valid", func(t *testing.T) {
		res := doRequestWithCookies(newNavigationRequest(ticketURL.String()), appNonce)
		require.Equal(t, 307, res.StatusCode)
		loc, err := res.Location()
		require.NoError(t, err)
		assert.Equal(t, "https://app.example.com/page?q=1", loc.String())

		hostToken := findResponseCookie(res, "__Host-_forward_auth")
		require.NotNil(t, hostToken)
		assert.Equal(t, "", hostToken.Domain)
		user, err := token.VerifyHostToken(hostToken.Value, "app.example.com", config.secretBytes)
		require.NoError(t, err)
		assert.Equal(t, m{"email": "example@example.com"}, user)

		cleared := findResponseCookie(res, appNonce.Name)
		require.NotNil(t, cleared, "nonce cookie should be cleared")
		assert.Equal(t, "", cleared.Value)

		res = doRequestWithCookies(newHTTPRequest("GET", "https://app.example.com/page"), hostToken)
		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, []string{"example@example.com"}, res.Header["X-Forwarded-User"])
	})
}

func TestAuthorizeRejectsForeignRedirect(t *testing.T) {
	initAuthHostTestConfig(t)
	n := strings.Repeat("a", 64)

	authorize := func(host, rd string) int {
		target := "https://" + host + "/_oauth/authorize?" + url.Values{"rd": {rd}, "n": {n}}.Encode()
		return doRequestWithCookies(newNavigationRequest(target)).StatusCode
	}

	assert.Equal(t, 307, authorize("auth.example.com", "https://app.example.com/"))
	assert.Equal(t, 307, authorize("auth.example.com", "https://example.com/"))
	assert.Equal(t, 400, authorize("auth.example.com", "https://evilexample.com/"), "suffix-only match should be rejected")
	assert.Equal(t, 400, authorize("auth.example.com", "https://other.org/"))
	assert.Equal(t, 400, authorize("auth.example.com", "javascript://app.example.com/"))
	// A ticket in an http URL could be read on the network and presented with the reader's own nonce cookie.
	assert.Equal(t, 400, authorize("auth.example.com", "http://app.example.com/"), "http redirect should be rejected with secure cookies")
	assert.Equal(t, 404, authorize("app.example.com", "https://app.example.com/"), "only auth hosts serve authorize")

	target := "https://auth.example.com/_oauth/authorize?" + url.Values{"rd": {"https://app.example.com/"}, "n": {"short"}}.Encode()
	assert.Equal(t, 400, doRequestWithCookies(newNavigationRequest(target)).StatusCode, "invalid nonce hash should be rejected")
}

func TestSoftAuthProbe(t *testing.T) {
	initAuthHostTestConfig(t)
	config.Rules["default"].Action = "soft-auth"

	t.Run("navigation without host token probes the provider", func(t *testing.T) {
		res := doRequestWithCookies(newNavigationRequest("https://app.example.com/page"))
		require.Equal(t, 307, res.StatusCode)
		loc, _ := res.Location()
		assert.Equal(t, "auth.example.com", loc.Host)
		assert.Equal(t, "1", loc.Query().Get("probe"))
		probe := findResponseCookie(res, "__Host-_forward_auth_probed")
		require.NotNil(t, probe)
		assert.NotEmpty(t, probe.Value)
	})

	t.Run("probed request passes anonymously", func(t *testing.T) {
		r := newNavigationRequest("https://app.example.com/page")
		r.Header.Set("X-Forwarded-User", "spoofed")
		res := doRequestWithCookies(r, &http.Cookie{Name: "__Host-_forward_auth_probed", Value: "1"})
		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, []string{""}, res.Header["X-Forwarded-User"])
	})

	t.Run("non-navigation request passes anonymously", func(t *testing.T) {
		res := doRequestWithCookies(newHTTPRequest("GET", "https://app.example.com/api"))
		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, []string{""}, res.Header["X-Forwarded-User"])

		r := newNavigationRequest("https://app.example.com/form")
		r.Method = "POST"
		r.Header.Set("X-Forwarded-Method", "POST")
		res = doRequestWithCookies(r)
		assert.Equal(t, 200, res.StatusCode, "POST navigation should not be redirected")
	})

	// account_selection_required is one of the prompt=none errors in OIDC Core 3.1.2.6, besides login_required.
	for _, providerError := range []string{"login_required", "account_selection_required", "server_error"} {
		t.Run("probe answered with "+providerError+" returns without ticket", func(t *testing.T) {
			res := doRequestWithCookies(newNavigationRequest("https://app.example.com/page"))
			authorizeURL, _ := res.Location()
			res = doRequestWithCookies(newNavigationRequest(authorizeURL.String()))
			require.Equal(t, 307, res.StatusCode)
			authNonce := findResponseCookieWithPrefix(res, "__Host-_forward_auth_csrf_")
			providerURL, _ := res.Location()
			assert.Equal(t, "none", providerURL.Query().Get("prompt"))

			callback := "https://auth.example.com/_oauth?" + url.Values{"error": {providerError}, "state": {providerURL.Query().Get("state")}}.Encode()
			res = doRequestWithCookies(newNavigationRequest(callback), authNonce)
			require.Equal(t, 307, res.StatusCode)
			loc, _ := res.Location()
			assert.Equal(t, "https://app.example.com/page", loc.String())
		})
	}

	t.Run("ticket exchange clears the probe mark", func(t *testing.T) {
		appNonce, ticketURL := loginFlow(t, newNavigationRequest("https://app.example.com/page"))
		res := doRequestWithCookies(newNavigationRequest(ticketURL.String()), appNonce, &http.Cookie{Name: "__Host-_forward_auth_probed", Value: "1"})
		require.Equal(t, 307, res.StatusCode)
		probe := findResponseCookie(res, "__Host-_forward_auth_probed")
		require.NotNil(t, probe)
		assert.Equal(t, "", probe.Value)
		assert.True(t, probe.Expires.Before(time.Now()))
	})

	t.Run("logout sets the probe mark", func(t *testing.T) {
		config.Rules["logout"] = &Rule{Action: "logout", RouteRule: "Path(`/_oauth/logout`)", Priority: 1, AuthRule: "True()"}
		res := doRequestWithCookies(newNavigationRequest("https://app.example.com/_oauth/logout"))
		require.Equal(t, 307, res.StatusCode)
		probe := findResponseCookie(res, "__Host-_forward_auth_probed")
		require.NotNil(t, probe)
		assert.NotEmpty(t, probe.Value)
		hostToken := findResponseCookie(res, "__Host-_forward_auth")
		require.NotNil(t, hostToken)
		assert.Equal(t, "", hostToken.Value)
	})

	t.Run("logout cancels logins in progress on the host", func(t *testing.T) {
		config.Rules["logout"] = &Rule{Action: "logout", RouteRule: "Path(`/_oauth/logout`)", Priority: 1, AuthRule: "True()"}
		appNonce, ticketURL := loginFlow(t, newNavigationRequest("https://app.example.com/page"))

		res := doRequestWithCookies(newNavigationRequest("https://app.example.com/_oauth/logout"), appNonce)
		require.Equal(t, 307, res.StatusCode)
		cleared := findResponseCookie(res, appNonce.Name)
		require.NotNil(t, cleared, "nonce cookie should be cleared on logout")
		assert.Equal(t, "", cleared.Value)
		assert.True(t, cleared.Expires.Before(time.Now()))

		// The browser no longer sends the cleared nonce cookie, so the ticket of the cancelled login is rejected.
		res = doRequestWithCookies(newNavigationRequest(ticketURL.String()))
		assert.Equal(t, 401, res.StatusCode)
	})
}

func TestBuiltinPathsTakePrecedenceOverRules(t *testing.T) {
	initAuthHostTestConfig(t)
	config.Rules["hard"] = &Rule{Action: "auth", RouteRule: "Header(`X-Forward-Auth-Type`, `hard`)", AuthRule: "True()"}

	r := newNavigationRequest("https://app.example.com/_oauth/ticket?t=invalid")
	r.Header.Set("X-Forward-Auth-Type", "hard")
	res := doRequestWithCookies(r)
	assert.Equal(t, 401, res.StatusCode, "ticket endpoint should be handled before user rules")

	r = newNavigationRequest("https://auth.example.com/_oauth?state=invalid")
	r.Header.Set("X-Forward-Auth-Type", "hard")
	res = doRequestWithCookies(r)
	assert.Equal(t, 401, res.StatusCode, "callback should be handled before user rules")

	r = newNavigationRequest("https://auth.example.com/_oauth/authorize?" + url.Values{"rd": {"https://app.example.com/"}, "n": {strings.Repeat("a", 64)}}.Encode())
	r.Header.Set("X-Forward-Auth-Type", "hard")
	res = doRequestWithCookies(r)
	require.Equal(t, 307, res.StatusCode)
	loc, _ := res.Location()
	assert.Equal(t, "accounts.google.com", loc.Host, "authorize should be handled before user rules")
}

func TestLegacyCookieIsCleared(t *testing.T) {
	initAuthHostTestConfig(t)
	legacy := &http.Cookie{Name: "_forward_auth", Value: "old"}

	assertCleared := func(t *testing.T, res *http.Response) {
		c := findResponseCookie(res, "_forward_auth")
		require.NotNil(t, c, "legacy cookie should be cleared")
		assert.Equal(t, "example.com", c.Domain)
		assert.True(t, c.Expires.Before(time.Now()))
	}

	t.Run("on login start", func(t *testing.T) {
		res := doRequestWithCookies(newNavigationRequest("https://app.example.com/page"), legacy)
		require.Equal(t, 307, res.StatusCode)
		assertCleared(t, res)
	})

	t.Run("on soft-auth probe", func(t *testing.T) {
		config.Rules["default"].Action = "soft-auth"
		t.Cleanup(func() { config.Rules["default"].Action = "auth" })
		res := doRequestWithCookies(newNavigationRequest("https://app.example.com/page"), legacy)
		require.Equal(t, 307, res.StatusCode)
		loc, _ := res.Location()
		require.Equal(t, "1", loc.Query().Get("probe"))
		assertCleared(t, res)
	})

	t.Run("on ticket exchange", func(t *testing.T) {
		appNonce, ticketURL := loginFlow(t, newNavigationRequest("https://app.example.com/page"))
		res := doRequestWithCookies(newNavigationRequest(ticketURL.String()), appNonce, legacy)
		require.Equal(t, 307, res.StatusCode)
		assertCleared(t, res)
	})

	t.Run("on a host outside auth domains", func(t *testing.T) {
		res := doRequestWithCookies(newNavigationRequest("https://other.com/page"), legacy)
		require.Equal(t, 307, res.StatusCode)
		c := findResponseCookie(res, "_forward_auth")
		require.NotNil(t, c, "legacy cookie should be cleared")
		assert.Equal(t, "other.com", c.Domain, "the legacy cookie of such a host was set on the host itself")
	})

	t.Run("not without legacy cookie", func(t *testing.T) {
		res := doRequestWithCookies(newNavigationRequest("https://app.example.com/page"))
		assert.Nil(t, findResponseCookie(res, "_forward_auth"))
	})
}
