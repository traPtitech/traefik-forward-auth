package tfa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/traPtitech/traefik-forward-auth/internal/token"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/traPtitech/traefik-forward-auth/internal/provider"
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

// ValidateRedirect validates that the given redirect is valid and permitted for
// the given request
func ValidateRedirect(r *http.Request, redirect string) (*url.URL, error) {
	redirectURL, err := url.Parse(redirect)

	if err != nil {
		return nil, errors.New("unable to parse redirect")
	}

	if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		return nil, errors.New("invalid redirect URL scheme")
	}

	// If we're using an auth domain?
	if use, base := useAuthDomain(r); use {
		// If we are using an auth domain, they redirect must share a common
		// suffix with the requested redirect
		if !strings.HasSuffix(redirectURL.Host, base) {
			return nil, errors.New("redirect host does not match any expected hosts (should match cookie domain when using auth host)")
		}
	} else {
		// If not, we should only ever redirect to the same domain
		if redirectURL.Host != r.Header.Get("X-Forwarded-Host") {
			return nil, errors.New("redirect host does not match request host (must match when not using auth host)")
		}
	}

	return redirectURL, nil
}

// Utility methods

// Get the request base from forwarded request
func redirectBase(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.Header.Get("X-Forwarded-Proto"), r.Host)
}

// Return url
func currentUrl(r *http.Request) string {
	return fmt.Sprintf("%s%s", redirectBase(r), r.URL.Path)
}

// Get oauth redirect uri
func redirectUri(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		p := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", p, config.AuthHost, config.URLPath)
	}

	return fmt.Sprintf("%s%s", redirectBase(r), config.URLPath)
}

// Should we use auth host + what it is
func useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Host)

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeCookie creates an auth cookie
func MakeCookie(r *http.Request, object any) (*http.Cookie, error) {
	expires := cookieExpiry()
	value, err := token.SignToken(object, expires.Unix(), config.secretBytes)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(r.Host),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  expires,
	}, nil
}

// ClearCookie clears the auth cookie
func ClearCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(r.Host),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

func buildCSRFCookieName(nonce string) string {
	return config.CSRFCookieName + "_" + nonce[:6]
}

// MakeCSRFCookie makes a csrf cookie (used during login only)
//
// Note, CSRF cookies live shorter than auth cookies, a fixed 1h.
// That's because some CSRF cookies may belong to auth flows that don't complete
// and thus may not get cleared by ClearCookie.
func MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     buildCSRFCookieName(nonce),
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * 1),
	}
}

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
func ClearCSRFCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// FindCSRFCookie extracts the CSRF cookie from the request based on state.
func FindCSRFCookie(r *http.Request, state string) (c *http.Cookie, err error) {
	// Check for CSRF cookie
	return r.Cookie(buildCSRFCookieName(state))
}

// ValidateCSRFCookie validates the csrf cookie against state
func ValidateCSRFCookie(c *http.Cookie, state string) (valid bool, provider string, redirect string, err error) {
	if len(c.Value) != 32 {
		return false, "", "", errors.New("invalid CSRF cookie value")
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", "", errors.New("CSRF cookie does not match state")
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New("invalid CSRF state format")
	}

	// Valid, return provider and redirect
	return true, params[:split], params[split+1:], nil
}

// MakeState generates a state value
func MakeState(returnUrl string, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl)
}

// ValidateState checks whether the state is of right length.
func ValidateState(state string) error {
	if len(state) < 34 {
		return errors.New("invalid CSRF state value")
	}
	return nil
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

// Cookie domain
func cookieDomain(requestHost string) string {
	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(requestHost)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Host
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range config.CookieDomains {
		if CookieDomainMatch(d, p[0]) {
			return true, d
		}
	}

	return false, p[0]
}

// Get cookie expiry
func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.lifetimeDuration)
}

// CookieDomain holds cookie domain info
type CookieDomain = string

// CookieDomainMatch checks if the given host matches this CookieDomain
func CookieDomainMatch(cd CookieDomain, host string) bool {
	// Exact domain match?
	if host == cd {
		return true
	}

	// Subdomain match?
	subDomain := fmt.Sprintf(".%s", cd)
	if len(host) >= len(subDomain) && host[len(host)-len(subDomain):] == subDomain {
		return true
	}

	return false
}
