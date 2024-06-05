package tfa

import (
	"fmt"
	"github.com/samber/lo"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

/**
 * Setup
 */

type m = map[string]any

func initTestConfig() *Config {
	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: very-secret
providers:
  google:
    client-id: id
    client-secret: secret
trusted-ip-addresses:
  - 127.0.0.2
`)
	config = lo.Must(NewConfig(tmpConfigFile))
	log = NewDefaultLogger(config)
	return config
}

/**
 * Tests
 */

func TestServerRootHandler(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// X-Forwarded headers should be read into request
	req := httptest.NewRequest("POST", "http://should-use-x-forwarded.com/should?ignore=me", nil)
	req.Header.Add("X-Forwarded-Method", "GET")
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Host", "example.com")
	req.Header.Add("X-Forwarded-Uri", "/foo?q=bar")
	NewServer().RootHandler(httptest.NewRecorder(), req)

	assert.Equal("GET", req.Method, "x-forwarded-method should be read into request")
	assert.Equal("example.com", req.Host, "x-forwarded-host should be read into request")
	assert.Equal("/foo", req.URL.Path, "x-forwarded-uri should be read into request")
	assert.Equal("/foo?q=bar", req.URL.RequestURI(), "x-forwarded-uri should be read into request")

	// Other X-Forwarded headers should be read in into request and original URL
	// should be preserved if X-Forwarded-Uri not present
	req = httptest.NewRequest("POST", "http://should-use-x-forwarded.com/should-not?ignore=me", nil)
	req.Header.Add("X-Forwarded-Method", "GET")
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Host", "example.com")
	NewServer().RootHandler(httptest.NewRecorder(), req)

	assert.Equal("GET", req.Method, "x-forwarded-method should be read into request")
	assert.Equal("example.com", req.Host, "x-forwarded-host should be read into request")
	assert.Equal("/should-not", req.URL.Path, "request url should be preserved if x-forwarded-uri not present")
	assert.Equal("/should-not?ignore=me", req.URL.RequestURI(), "request url should be preserved if x-forwarded-uri not present")
}

func TestServerAuthHandlerInvalid(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	var hook *test.Hook
	log, hook = test.NewNullLogger()

	// Should redirect vanilla request to login url
	req := newHTTPRequest("GET", "http://example.com/foo")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "vanilla request should be redirected")

	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "vanilla request should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "vanilla request should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "vanilla request should be redirected to google")

	// Check state string
	qs := fwd.Query()
	state, exists := qs["state"]
	require.True(t, exists)
	require.Len(t, state, 1)
	parts := strings.SplitN(state[0], ":", 3)
	require.Len(t, parts, 3)
	assert.Equal("google", parts[1])
	assert.Equal("http://example.com/foo", parts[2])

	// Should warn as using http without insecure cookie
	logs := hook.AllEntries()
	assert.Len(logs, 1)
	assert.Equal("You are using \"secure\" cookies for a request that was not "+
		"received via https. You should either redirect to https or pass the "+
		"\"insecure-cookie\" config option to permit cookies via http.", logs[0].Message)
	assert.Equal(logrus.WarnLevel, logs[0].Level)

	// Should catch invalid cookie
	req = newHTTPRequest("GET", "http://example.com/foo")
	c, err := MakeCookie(req, "test@example.com")
	assert.NoError(err)
	parts = strings.Split(c.Value, ".")
	c.Value = fmt.Sprintf("%s.%s.bad", parts[0], parts[1])

	res, _ = doHttpRequest(req, c)
	assert.Equal(307, res.StatusCode, "invalid cookie should not accepted")

	// Should validate email
	req = newHTTPRequest("GET", "http://example.com/foo")
	c, err = MakeCookie(req, "test@example.com")
	assert.NoError(err)
	config.Rules["default"].AuthRule = "Regexp(`email`, `^.+@test.com$`)"

	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "invalid email should not be authorised")
}

func TestServerAuthHandlerExpired(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	config.lifetimeDuration = time.Second * time.Duration(-1)
	config.Rules["default"].AuthRule = "Regexp(`email`, `^.+@test.com$`)"

	// Should redirect expired cookie
	req := newHTTPRequest("GET", "http://example.com/foo")
	c, err := MakeCookie(req, "test@example.com")
	assert.NoError(err)
	res, _ := doHttpRequest(req, c)
	require.Equal(t, 307, res.StatusCode, "request with expired cookie should be redirected")

	// Check for CSRF cookie
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, config.CSRFCookieName) {
			cookie = c
		}
	}
	assert.NotNil(cookie)

	// Check redirection location
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "request with expired cookie should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "request with expired cookie should be redirected to google")
}

func TestServerAuthHandlerValid(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	c, err := MakeCookie(req, m{"email": "test@example.com"})
	assert.NoError(err)

	res, _ := doHttpRequest(req, c)
	assert.Equal(200, res.StatusCode, "valid request should be allowed")

	// Should pass through user
	users := res.Header["X-Forwarded-User"]
	assert.Len(users, 1, "valid request should have X-Forwarded-User header")
	assert.Equal([]string{"test@example.com"}, users, "X-Forwarded-User header should match user")
}

func TestServerAuthHandlerTrustedIP_trusted(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	req.Header.Set("X-Forwarded-For", "127.0.0.2")

	res, _ := doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "trusted ip should be allowed")
}

func TestServerAuthHandlerTrustedIP_notTrusted(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "untrusted ip should not be allowed")
}

func TestServerAuthHandlerTrustedIP_invalidAddress(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	req.Header.Set("X-Forwarded-For", "127.0")

	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "invalid ip should not be allowed")
}

func TestServerAuthCallback(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	initTestConfig()

	// Setup OAuth server
	server, serverURL := NewOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}
	config.Providers.Google.UserURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/userinfo",
	}

	// Should pass auth response request to callback
	req := newHTTPRequest("GET", "http://example.com/_oauth")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(401, res.StatusCode, "auth callback without cookie shouldn't be authorised")

	// Should catch invalid csrf cookie
	nonce := "12345678901234567890123456789012"
	req = newHTTPRequest("GET", "http://example.com/_oauth?state="+nonce+":http://example.com")
	c := MakeCSRFCookie(req, "nononononononononononononononono")
	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "auth callback with invalid cookie shouldn't be authorised")

	// Should catch invalid provider cookie
	req = newHTTPRequest("GET", "http://example.com/_oauth?state="+nonce+":invalid:http://example.com")
	c = MakeCSRFCookie(req, nonce)
	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "auth callback with invalid provider shouldn't be authorised")

	// Should redirect valid request
	req = newHTTPRequest("GET", "http://example.com/_oauth?state="+nonce+":google:http://example.com")
	c = MakeCSRFCookie(req, nonce)
	res, _ = doHttpRequest(req, c)
	require.Equal(307, res.StatusCode, "valid auth callback should be allowed")

	fwd, _ := res.Location()
	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
	assert.Equal("example.com", fwd.Host, "valid request should be redirected to return url")
	assert.Equal("", fwd.Path, "valid request should be redirected to return url")
}

func TestServerAuthCallbackExchangeFailure(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Setup OAuth server
	server, serverURL := NewFailingOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}
	config.Providers.Google.UserURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/userinfo",
	}

	// Should handle failed code exchange
	req := newHTTPRequest("GET", "http://example.com/_oauth?state=12345678901234567890123456789012:google:http://example.com")
	c := MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ := doHttpRequest(req, c)
	assert.Equal(503, res.StatusCode, "auth callback should handle failed code exchange")
}

func TestServerAuthCallbackUserFailure(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Setup OAuth server
	server, serverURL := NewOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}
	serverFail, serverFailURL := NewFailingOAuthServer(t)
	defer serverFail.Close()
	config.Providers.Google.UserURL = &url.URL{
		Scheme: serverFailURL.Scheme,
		Host:   serverFailURL.Host,
		Path:   "/userinfo",
	}

	// Should handle failed user request
	req := newHTTPRequest("GET", "http://example.com/_oauth?state=12345678901234567890123456789012:google:http://example.com")
	c := MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ := doHttpRequest(req, c)
	assert.Equal(503, res.StatusCode, "auth callback should handle failed user request")
}

func TestServerLogout(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	initTestConfig()

	req := newHTTPRequest("GET", "http://example.com/_oauth/logout")
	res, _ := doHttpRequest(req, nil)
	require.Equal(307, res.StatusCode, "should return a 307")

	// Check for cookie
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == config.CookieName {
			cookie = c
		}
	}
	require.NotNil(cookie)
	require.Less(cookie.Expires.Local().Unix(), time.Now().Local().Unix()-50, "cookie should have expired")

	// Test with redirect
	req = newHTTPRequest("GET", "http://example.com/_oauth/logout?redirect=/path")
	res, _ = doHttpRequest(req, nil)
	require.Equal(307, res.StatusCode, "should return a 307")

	// Check for cookie
	cookie = nil
	for _, c := range res.Cookies() {
		if c.Name == config.CookieName {
			cookie = c
		}
	}
	require.NotNil(cookie)
	require.Less(cookie.Expires.Local().Unix(), time.Now().Local().Unix()-50, "cookie should have expired")

	fwd, _ := res.Location()
	require.NotNil(fwd)
	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
	assert.Equal("example.com", fwd.Host, "valid request should be redirected to return url")
	assert.Equal("/path", fwd.Path, "valid request should be redirected to return url")

}

func TestServerDefaultAction(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	req := newHTTPRequest("GET", "http://example.com/random")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request should require auth with auth default handler")

	config.Rules["default"].Action = "allow"
	req = newHTTPRequest("GET", "http://example.com/random")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request should be allowed with default handler")
}

func TestServerDefaultProvider(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	// Should use "google" as default provider when not specified
	req := newHTTPRequest("GET", "http://example.com/random")
	res, _ := doHttpRequest(req, nil)
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "request with expired cookie should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "request with expired cookie should be redirected to google")

	// Should use alternative default provider when set
	config.Provider = "oidc"
	config.Providers.OIDC.OAuthProvider.Config = &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://oidc.com/oidcauth",
		},
	}

	res, _ = doHttpRequest(req, nil)
	fwd, _ = res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to oidc")
	assert.Equal("oidc.com", fwd.Host, "request with expired cookie should be redirected to oidc")
	assert.Equal("/oidcauth", fwd.Path, "request with expired cookie should be redirected to oidc")
}

func TestServerRouteHeaders(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	config.Rules["1"] = &Rule{
		Action:    "allow",
		RouteRule: "Header(`X-Test`, `test123`)",
		AuthRule:  "True()",
	}
	config.Rules["2"] = &Rule{
		Action:    "allow",
		RouteRule: "HeaderRegexp(`X-Test`, `test(456|789)`)",
		AuthRule:  "True()",
	}

	// Should block any request
	req := newHTTPRequest("GET", "http://example.com/random")
	req.Header.Add("X-Random", "hello")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching
	req = newHTTPRequest("GET", "http://example.com/api")
	req.Header.Add("X-Test", "test123")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching
	req = newHTTPRequest("GET", "http://example.com/api")
	req.Header.Add("X-Test", "test789")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteHost(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	config.Rules["1"] = &Rule{
		Action:    "allow",
		RouteRule: "Host(`api.example.com`)",
		AuthRule:  "True()",
	}
	config.Rules["2"] = &Rule{
		Action:    "allow",
		RouteRule: "HostRegexp(`^sub[0-9].example.com$`)",
		AuthRule:  "True()",
	}

	// Should block any request
	req := newHTTPRequest("GET", "https://example.com/")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching request
	req = newHTTPRequest("GET", "https://api.example.com/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching request
	req = newHTTPRequest("GET", "https://sub8.example.com/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteMethod(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	config.Rules["1"] = &Rule{
		Action:    "allow",
		RouteRule: "Method(`PUT`)",
		AuthRule:  "True()",
	}

	// Should block any request
	req := newHTTPRequest("GET", "https://example.com/")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching request
	req = newHTTPRequest("PUT", "https://example.com/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRoutePath(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	config.Rules["1"] = &Rule{
		Action:    "allow",
		RouteRule: "Path(`/api`)",
		AuthRule:  "True()",
	}
	config.Rules["2"] = &Rule{
		Action:    "allow",
		RouteRule: "PathPrefix(`/private`)",
		AuthRule:  "True()",
	}

	// Should block any request
	req := newHTTPRequest("GET", "http://example.com/random")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow /api request
	req = newHTTPRequest("GET", "http://example.com/api")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow /private request
	req = newHTTPRequest("GET", "http://example.com/private")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	req = newHTTPRequest("GET", "http://example.com/private/path")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteQuery(t *testing.T) {
	assert := assert.New(t)
	initTestConfig()

	config.Rules["1"] = &Rule{
		Action:    "allow",
		RouteRule: "Query(`q`, `test123`)",
		AuthRule:  "True()",
	}

	// Should block any request
	req := newHTTPRequest("GET", "https://example.com/?q=no")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching request
	req = newHTTPRequest("GET", "https://api.example.com/?q=test123")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

/**
 * Utilities
 */

type OAuthServer struct {
	t    *testing.T
	fail bool
}

func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.fail {
		http.Error(w, "Service unavailable", 500)
		return
	}

	if r.URL.Path == "/token" {
		fmt.Fprintf(w, `{"access_token":"123456789"}`)
	} else if r.URL.Path == "/userinfo" {
		fmt.Fprint(w, `{
			"id":"1",
			"email":"example@example.com",
			"verified_email":true,
			"hd":"example.com"
		}`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.Method, r.URL)
	}
}

func NewOAuthServer(t *testing.T) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{}
	server := httptest.NewServer(handler)
	serverURL, _ := url.Parse(server.URL)
	return server, serverURL
}

func NewFailingOAuthServer(t *testing.T) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{fail: true}
	server := httptest.NewServer(handler)
	serverURL, _ := url.Parse(server.URL)
	return server, serverURL
}

func doHttpRequest(r *http.Request, c *http.Cookie) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Copy into request
	if c != nil {
		r.Header.Add("Cookie", c.String())
	}

	NewServer().RootHandler(w, r)

	res := w.Result()
	body := lo.Must(io.ReadAll(res.Body))

	// if res.StatusCode > 300 && res.StatusCode < 400 {
	// 	fmt.Printf("%#v", res.Header)
	// }

	return res, string(body)
}

func newHTTPRequest(method, target string) *http.Request {
	u, _ := url.Parse(target)
	r := httptest.NewRequest(method, target, nil)
	// https://doc.traefik.io/traefik/v3.0/middlewares/http/forwardauth/
	r.Header.Add("X-Forwarded-Method", method)
	r.Header.Add("X-Forwarded-Proto", u.Scheme)
	r.Header.Add("X-Forwarded-Host", u.Host)
	r.Header.Add("X-Forwarded-Uri", u.RequestURI())
	r.Header.Add("X-Forwarded-For", "127.0.0.1")
	return r
}
