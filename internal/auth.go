package tfa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/traPtitech/traefik-forward-auth/internal/token"
)

const (
	authorizePathSuffix = "/authorize"
	ticketPathSuffix    = "/ticket"

	// ticketLifetime bounds how long a ticket in a redirect URL stays usable.
	ticketLifetime = 30 * time.Second
	csrfLifetime   = time.Hour

	hostOnlyCookiePrefix = "__Host-"
)

// Request Validation

func GetRedirectURI(r *http.Request) string {
	redirect := r.URL.Query().Get("redirect")
	if redirect != "" {
		return redirect
	}
	forwardedURI := r.Header.Get("X-Forwarded-Uri")
	if forwardedURI != "" {
		u, err := url.ParseRequestURI(forwardedURI)
		if err == nil {
			redirect = u.Query().Get("redirect")
			if redirect != "" {
				return redirect
			}
		}
	}
	return "/"
}

func ValidateLoginRedirect(r *http.Request, redirect string) (*url.URL, error) {
	u, err := url.ParseRequestURI(redirect)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	requestScheme := r.Header.Get("X-Forwarded-Proto")
	requestHost := r.Header.Get("X-Forwarded-Host")
	if u.Scheme != "" && u.Scheme != requestScheme {
		return nil, fmt.Errorf("invalid redirect: scheme mismatch")
	}
	if u.Host != "" && u.Host != requestHost {
		return nil, fmt.Errorf("invalid redirect: host mismatch")
	}

	u.Scheme = requestScheme
	u.Host = requestHost
	return u, nil
}

func parseHTTPURL(redirect string) (*url.URL, error) {
	u, err := url.Parse(redirect)
	if err != nil {
		return nil, errors.New("unable to parse redirect")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("invalid redirect URL scheme")
	}
	return u, nil
}

// validateSameHostRedirect accepts an absolute http(s) URL on the request host.
func validateSameHostRedirect(r *http.Request, redirect string) (*url.URL, error) {
	u, err := parseHTTPURL(redirect)
	if err != nil {
		return nil, err
	}
	if u.Host != r.Host {
		return nil, errors.New("redirect host does not match request host")
	}
	return u, nil
}

// validateAuthHostRedirect accepts an absolute URL on a host that the auth host r.Host serves,
// i.e. the auth domain of r.Host itself or one of its subdomains.
// The URL must be https unless insecure-cookie is set, because the ticket for the host is sent with the same scheme.
func validateAuthHostRedirect(r *http.Request, redirect string) (*url.URL, error) {
	u, err := parseHTTPURL(redirect)
	if err != nil {
		return nil, err
	}
	if !config.InsecureCookie && u.Scheme != "https" {
		return nil, errors.New("redirect must be https")
	}
	domain, ok := config.authDomainOf(r.Host)
	if !ok || !domain.Contains(hostname(u.Host)) {
		return nil, errors.New("redirect host is not served by this auth host")
	}
	return u, nil
}

// Utility methods

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// Get the request base from forwarded request
func redirectBase(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.Header.Get("X-Forwarded-Proto"), r.Host)
}

// Return url
func currentUrl(r *http.Request) string {
	return redirectBase(r) + r.URL.RequestURI()
}

// Get oauth redirect uri: the callback on the host that receives the provider's response.
func redirectUri(r *http.Request) string {
	return redirectBase(r) + config.CallbackPath
}

// authHostFor returns the auth host through which host logs in.
// It fails when host belongs to no auth domain, or no auth host belongs to the same one.
func authHostFor(host string) (string, bool) {
	domain, ok := config.authDomainOf(host)
	if !ok {
		return "", false
	}
	for _, authHost := range config.AuthHost {
		if d, ok := config.authDomainOf(authHost); ok && d == domain {
			return authHost, true
		}
	}
	return "", false
}

func isPageNavigation(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		r.Header.Get("Sec-Fetch-Dest") == "document"
}

// Cookie methods

func cookieName(name string) string {
	if config.InsecureCookie {
		return name
	}
	return hostOnlyCookiePrefix + name
}

func hostTokenCookieName() string { return cookieName(config.CookieName) }

func probeCookieName() string { return cookieName(config.CookieName + "_probed") }

func csrfCookieName(nonceHash string) string {
	return cookieName(config.CSRFCookieName + "_" + nonceHash[:6])
}

// hostOnlyCookie makes a cookie without the Domain attribute, so that it is sent back only to the host that set it.
func hostOnlyCookie(name, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

func expiredHostOnlyCookie(name string) *http.Cookie {
	return hostOnlyCookie(name, "", time.Now().Add(-time.Hour))
}

// MakeCookie creates a host token cookie that authenticates user on r.Host only.
func MakeCookie(r *http.Request, user any) (*http.Cookie, error) {
	expires := cookieExpiry()
	value, err := token.SignHostToken(user, hostname(r.Host), expires, config.secretBytes)
	if err != nil {
		return nil, err
	}
	return hostOnlyCookie(hostTokenCookieName(), value, expires), nil
}

// ClearCookie clears the host token cookie
func ClearCookie() *http.Cookie {
	return expiredHostOnlyCookie(hostTokenCookieName())
}

// MakeProbeCookie marks that the provider has been asked whether the user is logged in,
// so that soft-auth passes the following requests anonymously instead of asking again.
func MakeProbeCookie() *http.Cookie {
	return hostOnlyCookie(probeCookieName(), "1", cookieExpiry())
}

// ClearProbeCookie clears the mark set by MakeProbeCookie.
func ClearProbeCookie() *http.Cookie {
	return expiredHostOnlyCookie(probeCookieName())
}

func hasProbeCookie(r *http.Request) bool {
	_, err := r.Cookie(probeCookieName())
	return err == nil
}

// MakeCSRFCookie makes a nonce cookie for one login flow.
// The cookie name contains a part of the nonce hash, so that concurrent flows (e.g. in multiple tabs) do not overwrite each other.
func MakeCSRFCookie(nonce string) *http.Cookie {
	return hostOnlyCookie(csrfCookieName(hashNonce(nonce)), nonce, time.Now().Add(csrfLifetime))
}

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
func ClearCSRFCookie(c *http.Cookie) *http.Cookie {
	return expiredHostOnlyCookie(c.Name)
}

// FindCSRFCookie returns the nonce cookie whose value hashes to nonceHash.
func FindCSRFCookie(r *http.Request, nonceHash string) (*http.Cookie, error) {
	if !isNonceHash(nonceHash) {
		return nil, errors.New("invalid nonce hash")
	}
	for _, c := range r.CookiesNamed(csrfCookieName(nonceHash)) {
		if subtle.ConstantTimeCompare([]byte(hashNonce(c.Value)), []byte(nonceHash)) == 1 {
			return c, nil
		}
	}
	return nil, errors.New("csrf cookie not found")
}

// findCSRFCookies returns all nonce cookies on this host, of any login flow.
func findCSRFCookies(r *http.Request) []*http.Cookie {
	prefix := cookieName(config.CSRFCookieName + "_")
	var cookies []*http.Cookie
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			cookies = append(cookies, c)
		}
	}
	return cookies
}

// clearLegacyCookie returns a cookie that deletes the auth cookie of the previous format,
// which was set on the whole auth domain, or nil if the request does not carry one.
//
// In insecure mode the legacy and current cookies share the name, and deleting the legacy one
// on a host without an auth domain would also delete the current one, so nothing is deleted.
func clearLegacyCookie(r *http.Request) *http.Cookie {
	if config.InsecureCookie {
		return nil
	}
	if _, err := r.Cookie(config.CookieName); err != nil {
		return nil
	}
	// The legacy cookie was set on the host itself when the host belongs to no auth domain.
	domain := hostname(r.Host)
	if d, ok := config.authDomainOf(r.Host); ok {
		domain = string(d)
	}
	return &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(-time.Hour),
	}
}

// State

// authState is carried through the provider in the "state" parameter.
type authState struct {
	// Nonce is the value of the nonce cookie on the host that receives the provider's response.
	Nonce    string
	Provider string
	// Probe is true when soft-auth asks the provider whether the user is logged in, without letting the user log in.
	Probe bool
	// AppNonceHash is the hash of the nonce cookie on the host that receives the ticket. Empty without an auth host.
	AppNonceHash string
	// Redirect is the URL to return to after login.
	Redirect string
}

func (s authState) String() string {
	probe := "0"
	if s.Probe {
		probe = "1"
	}
	return strings.Join([]string{s.Nonce, s.Provider, probe, s.AppNonceHash, s.Redirect}, ":")
}

func parseAuthState(state string) (authState, error) {
	parts := strings.SplitN(state, ":", 5)
	if len(parts) != 5 {
		return authState{}, errors.New("invalid state format")
	}
	s := authState{Nonce: parts[0], Provider: parts[1], AppNonceHash: parts[3], Redirect: parts[4]}
	if len(s.Nonce) != 32 {
		return authState{}, errors.New("invalid state nonce")
	}
	switch parts[2] {
	case "0":
	case "1":
		s.Probe = true
	default:
		return authState{}, errors.New("invalid state probe flag")
	}
	if s.AppNonceHash != "" && !isNonceHash(s.AppNonceHash) {
		return authState{}, errors.New("invalid state app nonce hash")
	}
	if s.Redirect == "" {
		return authState{}, errors.New("invalid state redirect")
	}
	return s, nil
}

// Nonce generates a random nonce
func Nonce() (error, string) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return err, ""
	}

	return nil, fmt.Sprintf("%x", nonce)
}

func hashNonce(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

func isNonceHash(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// authDomainOf returns the auth domain that host belongs to.
func (c *Config) authDomainOf(host string) (AuthDomain, bool) {
	h := hostname(host)
	for _, d := range c.AuthDomains {
		if d.Contains(h) {
			return d, true
		}
	}
	return "", false
}

func (c *Config) isAuthHost(host string) bool {
	h := hostname(host)
	for _, authHost := range c.AuthHost {
		if hostname(authHost) == h {
			return true
		}
	}
	return false
}

// Get cookie expiry
func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.lifetimeDuration)
}

// AuthDomain is a domain whose hosts log in via the auth host on the same domain.
type AuthDomain string

// Contains reports whether host is the domain itself or one of its subdomains.
// host must not include a port.
func (d AuthDomain) Contains(host string) bool {
	return host == string(d) || strings.HasSuffix(host, "."+string(d))
}
