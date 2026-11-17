package tfa

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/traPtitech/traefik-forward-auth/internal/authrule"
	"github.com/traPtitech/traefik-forward-auth/internal/provider"
	"github.com/traPtitech/traefik-forward-auth/internal/token"
	"github.com/traefik/traefik/v3/pkg/middlewares/requestdecorator"
	mux "github.com/traefik/traefik/v3/pkg/muxer/http"
)

// Server contains router and handler methods
type Server struct {
	muxer *mux.Muxer
	// reqDecorator is necessary for the Host matcher
	reqDecorator *requestdecorator.RequestDecorator
}

// NewServer creates a new server object and builds router
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func escapeNewlines(data string) string {
	escapedData := strings.Replace(data, "\n", "", -1)
	escapedData = strings.Replace(escapedData, "\r", "", -1)
	return escapedData
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = mux.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}
	s.reqDecorator = requestdecorator.New(nil)

	// Let's build a router
	const syntax = "v3"
	for name, rule := range config.Rules {
		// err should not occur because rule is validated beforehand
		priority := lo.Ternary(rule.Priority == 0, len(rule.RouteRule), rule.Priority)
		authPred := lo.Must(authrule.NewAuthRule(rule.AuthRule, config.InfoFields))
		handler := s.Handler(rule.Action, config.Provider, name, authPred)
		lo.Must0(s.muxer.AddRoute(rule.RouteRule, syntax, priority, handler))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so that it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request if we're acting as forward auth middleware
	// https://doc.traefik.io/traefik/v3.0/middlewares/http/forwardauth/
	if v := r.Header.Get("X-Forwarded-Method"); v != "" {
		r.Method = v
	}
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		r.Host = v
	}
	if v := r.Header.Get("X-Forwarded-Uri"); v != "" {
		r.URL, _ = url.Parse(v)
	}

	// The login flow is served before user-defined rules, so that no rule can intercept it.
	switch r.URL.Path {
	case config.CallbackPath:
		s.providerCallbackHandler(w, r)
		return
	case config.CallbackPath + authorizePathSuffix:
		s.authorizeHandler(w, r)
		return
	case config.CallbackPath + ticketPathSuffix:
		s.ticketHandler(w, r)
		return
	}

	// Pass to mux
	s.reqDecorator.ServeHTTP(w, r, s.muxer.ServeHTTP)
}

func (s *Server) Handler(action, providerName, rule string, authPred authrule.Predicate) http.HandlerFunc {
	switch action {
	case "allow":
		return s.allowHandler(rule)
	case "soft-auth":
		return s.softAuthHandler(providerName, rule, authPred)
	case "auth":
		return s.hardAuthHandler(providerName, rule, authPred)
	case "login":
		return s.LoginHandler(providerName)
	case "logout":
		return s.LogoutHandler()
	default:
		panic("unknown action " + action)
	}
}

// allowHandler Allows requests
func (s *Server) allowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// GetUserinfoFromCookie returns the user of a valid host token for r.Host, or nil if there is none.
func GetUserinfoFromCookie(r *http.Request) any {
	for _, c := range r.CookiesNamed(hostTokenCookieName()) {
		object, err := token.VerifyHostToken(c.Value, hostname(r.Host), config.secretBytes)
		if err == nil {
			return object
		}
	}
	return nil
}

// softAuthHandler Soft-authenticates requests
func (s *Server) softAuthHandler(providerName, rule string, authPred authrule.Predicate) http.HandlerFunc {
	return s.authHandler(providerName, rule, true, authPred)
}

// hardAuthHandler Authenticates requests
func (s *Server) hardAuthHandler(providerName, rule string, authPred authrule.Predicate) http.HandlerFunc {
	return s.authHandler(providerName, rule, false, authPred)
}

func (s *Server) authHandler(providerName, rule string, soft bool, authPred authrule.Predicate) http.HandlerFunc {
	p, _ := config.GetProvider(providerName)

	var unauthorized func(w http.ResponseWriter)
	if soft {
		unauthorized = func(w http.ResponseWriter) {
			// Set empty values before passing the request so that they cannot be impersonated
			for _, h := range config.Headers {
				w.Header().Set(h.Name, "")
			}
			w.WriteHeader(200)
		}
	} else {
		unauthorized = func(w http.ResponseWriter) {
			http.Error(w, "Unauthorized", 401)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		ipAddr := escapeNewlines(r.Header.Get("X-Forwarded-For"))
		if ipAddr == "" {
			logger.Warn("missing x-forwarded-for header")
		} else {
			ok, err := config.IsIPAddressAuthenticated(ipAddr)
			if err != nil {
				logger.WithField("error", err).Warn("Invalid forwarded for")
			} else if ok {
				logger.WithField("addr", ipAddr).Info("Authenticated remote address")
				w.WriteHeader(200)
				return
			}
		}

		// Get user from cookie
		userinfo := GetUserinfoFromCookie(r)
		if userinfo == nil {
			switch {
			case !soft:
				s.startLogin(logger, w, r, p, currentUrl(r), false)
			case hasProbeCookie(r) || !isPageNavigation(r):
				// A redirect can only be followed by a page navigation,
				// and the probe mark records that the provider already answered "not logged in".
				unauthorized(w)
			default:
				http.SetCookie(w, MakeProbeCookie())
				s.startLogin(logger, w, r, p, currentUrl(r), true)
			}
			return
		}

		// Check that the token has expected fields
		for _, field := range config.InfoFields {
			token.GetPathStr(userinfo, field)
		}

		// Validate user
		valid := authPred(userinfo)
		if !valid {
			logger.WithField("userinfo", escapeNewlines(fmt.Sprintf("%v", userinfo))).Warn("Invalid user")
			unauthorized(w)
			return
		}

		// Valid request
		logger.Debug("Allowing valid request")
		for _, h := range config.Headers {
			str, _ := token.GetPathStr(userinfo, h.Source)
			w.Header().Set(h.Name, str)
		}
		w.WriteHeader(200)
	}
}

// startLogin redirects the user to log in and come back to returnUrl on this host.
// With an auth host the login goes through the auth host and comes back with a ticket;
// otherwise this host receives the provider's response itself.
// probe asks the provider without letting the user log in (see authState.Probe).
func (s *Server) startLogin(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider, returnUrl string, probe bool) {
	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}
	if c := clearLegacyCookie(r); c != nil {
		http.SetCookie(w, c)
	}

	authHost, ok := authHostFor(r.Host)
	if !ok {
		s.redirectToProvider(logger, w, r, p, authState{Provider: p.Name(), Probe: probe, Redirect: returnUrl}, loginPrompt(probe))
		return
	}

	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}
	http.SetCookie(w, MakeCSRFCookie(nonce))

	q := url.Values{"rd": {returnUrl}, "n": {hashNonce(nonce)}}
	if probe {
		q.Set("probe", "1")
	}
	authorizeURL := fmt.Sprintf("%s://%s%s%s?%s", r.Header.Get("X-Forwarded-Proto"), authHost, config.CallbackPath, authorizePathSuffix, q.Encode())
	http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
}

func loginPrompt(probe bool) provider.Prompt {
	return lo.Ternary(probe, provider.PromptNone, provider.PromptConfigured)
}

// redirectToProvider sets a fresh nonce cookie on this host, and redirects to the provider with state carrying the nonce.
func (s *Server) redirectToProvider(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider, state authState, prompt provider.Prompt) {
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}
	csrf := MakeCSRFCookie(nonce)
	http.SetCookie(w, csrf)

	state.Nonce = nonce
	loginURL := p.GetLoginURL(redirectUri(r), state.String(), prompt)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

// authorizeHandler starts a login on the auth host on behalf of the host in "rd".
func (s *Server) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	logger := s.logger(r, "Authorize", "default", "Handling authorize")

	if !config.isAuthHost(r.Host) {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	redirectURL, err := validateAuthHostRedirect(r, q.Get("rd"))
	if err != nil {
		logger.WithField("received_redirect", escapeNewlines(q.Get("rd"))).Warnf("Invalid redirect in authorize: %v", err)
		http.Error(w, "Invalid redirect", 400)
		return
	}
	appNonceHash := q.Get("n")
	if !isNonceHash(appNonceHash) {
		logger.Warn("Invalid nonce hash in authorize")
		http.Error(w, "Invalid nonce", 400)
		return
	}
	probe := q.Get("probe") == "1"

	p, _ := config.GetProvider(config.Provider)
	state := authState{Provider: p.Name(), Probe: probe, AppNonceHash: appNonceHash, Redirect: redirectURL.String()}
	s.redirectToProvider(logger, w, r, p, state, loginPrompt(probe))
}

// providerCallbackHandler handles the provider's response on the auth host, or on the host itself without an auth host.
func (s *Server) providerCallbackHandler(w http.ResponseWriter, r *http.Request) {
	logger := s.logger(r, "AuthCallback", "default", "Handling callback")

	state, err := parseAuthState(r.URL.Query().Get("state"))
	if err != nil {
		logger.WithField("error", err).Warn("Error validating state")
		http.Error(w, "Not authorized", 401)
		return
	}

	c, err := FindCSRFCookie(r, hashNonce(state.Nonce))
	if err != nil {
		logger.WithField("error", err).Info("Missing csrf cookie")
		http.Error(w, "Not authorized", 401)
		return
	}

	p, err := config.GetProvider(state.Provider)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error":    err,
			"provider": escapeNewlines(state.Provider),
		}).Warn("Invalid provider in state")
		http.Error(w, "Not authorized", 401)
		return
	}

	http.SetCookie(w, ClearCSRFCookie(c))

	// Whether this host hands over the login with a ticket is decided by the config, not by the state.
	viaAuthHost := config.isAuthHost(r.Host)
	var redirectURL *url.URL
	if viaAuthHost {
		redirectURL, err = validateAuthHostRedirect(r, state.Redirect)
		if err == nil && state.AppNonceHash == "" {
			err = errors.New("missing app nonce hash")
		}
	} else {
		redirectURL, err = validateSameHostRedirect(r, state.Redirect)
	}
	if err != nil {
		logger.WithField("received_redirect", escapeNewlines(state.Redirect)).Warnf("Invalid redirect in state: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	authError := r.URL.Query().Get("error")
	if authError != "" && state.Probe {
		// The provider did not log the user in silently; return anonymously. The probe mark on the host prevents asking again.
		logger.WithField("provider_error", escapeNewlines(authError)).Debug("Probe answered without login")
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
		return
	}
	if authError == "login_required" || authError == "consent_required" || authError == "interaction_required" {
		// Retry without the 'prompt' parameter (which was possibly 'none' or some other value)
		s.redirectToProvider(logger, w, r, p, state, provider.PromptOmit)
		return
	}
	if authError != "" {
		// Other errors such as provider server error
		logger.WithField("provider_error", escapeNewlines(authError)).Error("Authorize failed with provider")
		http.Error(w, "Provider error", 500)
		return
	}

	// Exchange code for token
	oauthToken, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
	if err != nil {
		logger.WithField("error", err).Error("Code exchange failed with provider")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Get userinfo
	userinfo, err := p.GetUser(oauthToken)
	if err != nil {
		logger.WithField("error", err).Error("Error getting user")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Limit fields from raw userinfo
	userinfo, err = token.LimitFields(userinfo, config.InfoFields)
	if err != nil {
		logger.WithField("error", err).Error("Error limiting fields from raw userinfo")
		http.Error(w, "Internal server error", 500)
		return
	}

	if !viaAuthHost {
		if !s.setHostToken(logger, w, r, userinfo) {
			return
		}
		logger.WithFields(logrus.Fields{
			"provider": state.Provider,
			"redirect": redirectURL.String(),
			"userinfo": userinfo,
		}).Info("Successfully generated auth cookie, redirecting user.")
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
		return
	}

	ticket := token.Ticket{User: userinfo, NonceHash: state.AppNonceHash, Redirect: redirectURL.String()}
	signed, err := token.SignTicket(ticket, hostname(redirectURL.Host), time.Now().Add(ticketLifetime), config.secretBytes)
	if err != nil {
		logger.WithField("error", err).Error("Error signing ticket")
		http.Error(w, "Internal server error", 500)
		return
	}
	ticketURL := url.URL{
		Scheme:   redirectURL.Scheme,
		Host:     redirectURL.Host,
		Path:     config.CallbackPath + ticketPathSuffix,
		RawQuery: url.Values{"t": {signed}}.Encode(),
	}
	logger.WithFields(logrus.Fields{
		"provider": state.Provider,
		"redirect": redirectURL.String(),
		"userinfo": userinfo,
	}).Info("Successfully issued ticket, redirecting user.")
	http.Redirect(w, r, ticketURL.String(), http.StatusTemporaryRedirect)
}

// ticketHandler exchanges a ticket from the auth host for a host token on this host.
func (s *Server) ticketHandler(w http.ResponseWriter, r *http.Request) {
	logger := s.logger(r, "Ticket", "default", "Handling ticket")

	reject := func(reason string, err error) {
		logger.WithFields(logrus.Fields{
			"reason": reason,
			"error":  err,
		}).Warn("Rejected ticket")
		http.Error(w, "Not authorized", 401)
	}

	ticket, err := token.VerifyTicket(r.URL.Query().Get("t"), hostname(r.Host), config.secretBytes)
	switch {
	case errors.Is(err, token.ErrAudience):
		reject("audience", err)
		return
	case errors.Is(err, token.ErrExpired):
		reject("expired", err)
		return
	case errors.Is(err, token.ErrKind):
		reject("kind", err)
		return
	case err != nil:
		reject("invalid", err)
		return
	}

	c, err := FindCSRFCookie(r, ticket.NonceHash)
	if err != nil {
		reject("nonce", err)
		return
	}

	redirectURL, err := validateSameHostRedirect(r, ticket.Redirect)
	if err != nil {
		reject("redirect", err)
		return
	}

	http.SetCookie(w, ClearCSRFCookie(c))
	if !s.setHostToken(logger, w, r, ticket.User) {
		return
	}
	logger.WithField("userinfo", ticket.User).Info("Successfully exchanged ticket, redirecting user.")
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

// setHostToken sets the host token for user on r.Host, and clears the probe mark and the legacy cookie.
// It writes an error response and returns false on failure.
func (s *Server) setHostToken(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, user any) bool {
	cookie, err := MakeCookie(r, user)
	if err != nil {
		logger.WithField("error", err).Error("Error making cookie")
		http.Error(w, "Internal server error", 500)
		return false
	}
	http.SetCookie(w, cookie)
	http.SetCookie(w, ClearProbeCookie())
	if c := clearLegacyCookie(r); c != nil {
		http.SetCookie(w, c)
	}
	return true
}

// LoginHandler logs a user in
func (s *Server) LoginHandler(providerName string) http.HandlerFunc {
	p, _ := config.GetProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Login", "default", "Handling login")
		logger.Info("Explicit user login")

		// Calculate and validate redirect
		redirect := GetRedirectURI(r)
		redirectURL, err := ValidateLoginRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"received_redirect": redirect,
			}).Warnf("Invalid redirect in login: %v", err)
			http.Error(w, "Invalid redirect: "+err.Error(), 400)
			return
		}

		// Get user
		userinfo := GetUserinfoFromCookie(r)
		if userinfo != nil { // Already logged in
			http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
			return
		}

		// Login
		s.startLogin(logger, w, r, p, redirectURL.String(), false)
	}
}

// LogoutHandler logs a user out of this host
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		// Clear cookie, and keep soft-auth from logging the user in again on the next page.
		// Nonce cookies are cleared too, so that a login started before logging out cannot complete after it.
		http.SetCookie(w, ClearCookie())
		http.SetCookie(w, MakeProbeCookie())
		for _, c := range findCSRFCookies(r) {
			http.SetCookie(w, ClearCSRFCookie(c))
		}

		// Calculate and validate redirect
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/"
		}
		redirectURL, err := ValidateLoginRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"received_redirect": redirect,
			}).Warnf("Invalid redirect in login: %v", err)
			http.Error(w, "Invalid redirect: "+err.Error(), 400)
			return
		}

		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    escapeNewlines(r.Header.Get("X-Forwarded-Method")),
		"proto":     escapeNewlines(r.Header.Get("X-Forwarded-Proto")),
		"host":      escapeNewlines(r.Header.Get("X-Forwarded-Host")),
		"uri":       escapeNewlines(r.Header.Get("X-Forwarded-Uri")),
		"source_ip": escapeNewlines(r.Header.Get("X-Forwarded-For")),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}
