package tfa

import (
	"fmt"
	"github.com/traPtitech/traefik-forward-auth/internal/authrule"
	"github.com/traPtitech/traefik-forward-auth/internal/token"
	"github.com/traefik/traefik/v3/pkg/middlewares/requestdecorator"
	"net/http"
	"net/url"
	"strings"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	mux "github.com/traefik/traefik/v3/pkg/muxer/http"

	"github.com/traPtitech/traefik-forward-auth/internal/provider"
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
	case "callback":
		return s.AuthCallbackHandler()
	case "login":
		return s.LoginHandler(providerName)
	case "logout":
		return s.LogoutHandler()
	case "health":
		return s.healthCheckHandler()
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

func GetUserinfoFromCookie(r *http.Request) any {
	// Get auth cookie
	c, err := r.Cookie(config.CookieName)
	if err != nil {
		return nil
	}

	// Validate cookie
	object, err := token.VerifyToken(c.Value, config.secretBytes)
	if err != nil {
		return nil
	}
	return object
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
			if soft {
				unauthorized(w)
				return
			} else {
				s.authRedirect(logger, w, r, p, currentUrl(r), true)
				return
			}
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

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := escapeNewlines(r.URL.Query().Get("state"))
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Validate redirect
		redirectURL, err := ValidateRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"received_redirect": redirect,
			}).Warnf("Invalid redirect in CSRF. %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check error
		authError := r.URL.Query().Get("error")
		if authError == "login_required" || authError == "consent_required" {
			// Retry without the 'prompt' parameter (which was possibly 'none' or some other value)
			s.authRedirect(logger, w, r, p, redirect, false)
			return
		}
		if authError != "" {
			// Other errors such as provider server error
			logger.WithField("provider_error", authError).Error("Authorize failed with provider")
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

		// Generate cookie
		cookie, err := MakeCookie(r, userinfo)
		if err != nil {
			logger.WithField("error", err).Error("Error making cookie")
			http.Error(w, "Internal server error", 500)
		}
		http.SetCookie(w, cookie)
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"userinfo": userinfo,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}
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
		s.authRedirect(logger, w, r, p, redirectURL.String(), true)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

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

func (s *Server) healthCheckHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider, returnUrl string, allowPrompt bool) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// clean existing CSRF cookie
	for _, v := range r.Cookies() {
		if strings.Contains(v.Name, config.CSRFCookieName) {
			http.SetCookie(w, ClearCSRFCookie(r, v))
		}
	}
	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(returnUrl, p, nonce), allowPrompt)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
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
