package tfa

import (
	"errors"
	"fmt"
	"github.com/samber/lo"
	"github.com/spf13/viper"
	"github.com/traPtitech/traefik-forward-auth/internal/authrule"
	"net"
	"os"
	"strings"
	"time"

	"github.com/traPtitech/traefik-forward-auth/internal/provider"
)

var config *Config

// Config holds the runtime application config
type Config struct {
	// LogLevel defines logrus log level.
	// 	Allowed values: "trace", "debug", "info", "warn", "error", "fatal", "panic"
	LogLevel string `mapstructure:"log-level"`
	// LogFormat defines logrus log format.
	// 	Allowed values: "text", "json", "pretty"
	LogFormat string `mapstructure:"log-format"`

	// AuthHost defines a single host to use when returning from 3rd party auth.
	AuthHost string `mapstructure:"auth-host"`
	// CookieDomains defines domains to set auth cookie on. Comma separated.
	CookieDomains []CookieDomain `mapstructure:"cookie-domains"`
	// InsecureCookie specifies to use insecure cookies.
	InsecureCookie bool `mapstructure:"insecure-cookie"`
	// CookieName defines cookie name to use.
	CookieName string `mapstructure:"cookie-name"`
	// CSRFCookieName defines CSRF cookie name to use.
	CSRFCookieName string `mapstructure:"csrf-cookie-name"`
	// Lifetime defines cookie lifetime in seconds.
	Lifetime int `mapstructure:"lifetime"`
	// CallbackPath defines callback URL path.
	CallbackPath string `mapstructure:"callback-path"`
	// Secret defines secret used for signing a token (required).
	Secret string `mapstructure:"secret"`
	// TrustedIPAddresses define list of trusted IP addresses or IP networks (in CIDR notation) that are considered authenticated. Comma separated.
	TrustedIPAddresses []string `mapstructure:"trusted-ip-addresses"`
	// Port defines port to listen on.
	Port int `mapstructure:"port"`
	// InfoFields define dot notation of userinfo fields to save to the token.
	// Note that fields not specified here will not be saved to the token.
	// Since traefik-forward-auth is a stateless application, fields not specified here cannot be referenced from
	// `rules.<name>.auth-rule` or `headers.<name>.source`.
	InfoFields []string `mapstructure:"info-fields"`

	// Provider selects provider to use.
	// 	Allowed values: "google", "oidc", "generic-oauth"
	Provider string `mapstructure:"provider"`
	// Providers define auth providers.
	Providers provider.Providers `mapstructure:"providers"`
	// Rules define routing and auth mode rules.
	Rules map[string]*Rule `mapstructure:"rules"`
	// Headers map userinfo sources and header names to pass on.
	Headers map[string]*Header `mapstructure:"headers"`

	// Filled during transformations
	secretBytes       []byte
	lifetimeDuration  time.Duration
	trustedIPNetworks []*net.IPNet
}

func init() {
	// Automatically load from respective environment variables
	viper.AutomaticEnv()
	// Allow getting underscore-delimited environment variables via dot-delimited or hyphen-delimited key values
	// e.g. viper.Get("foo.bar") will lookup "FOO_BAR" environment variable so these can be mapped to structs
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	// NOTE: Building with build tag "viper_bind_struct" allows binding dynamic struct fields from environment variables,
	// even without explicitly letting viper "know" that a key exists via viper.SetDefault() etc.
	// In the future, this feature flag might change: https://github.com/spf13/viper/issues/1851

	// Set defaults
	viper.SetDefault("log-level", "warn")
	viper.SetDefault("log-format", "text")

	viper.SetDefault("cookie-name", "_forward_auth")
	viper.SetDefault("csrf-cookie-name", "_forward_auth_csrf")
	viper.SetDefault("lifetime", "43200")
	viper.SetDefault("callback-path", "/_oauth")
	viper.SetDefault("user-id-path", "email")
	viper.SetDefault("port", "4181")
	viper.SetDefault("info-fields", "email")

	viper.SetDefault("provider", "google")
	viper.SetDefault("providers.google.prompt", "select_account")
	viper.SetDefault("providers.oidc.scopes", "profile,email")
	viper.SetDefault("providers.generic-oauth.token-style", "header")
	viper.SetDefault("providers.generic-oauth.scopes", "profile,email")

	// Rules default values are defined in (*Config).setup below.

	viper.SetDefault("headers.default.name", "X-Forwarded-User")
	viper.SetDefault("headers.default.source", "email")
}

// NewGlobalConfig creates a new global config
func NewGlobalConfig(location string) *Config {
	var err error
	config, err = NewConfig(location)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
	return config
}

// NewConfig parses configuration into a config object
func NewConfig(location string) (*Config, error) {
	var c Config

	if location != "" {
		viper.SetConfigFile(location)
		err := viper.ReadInConfig()
		if err != nil {
			return nil, err
		}
	}

	err := viper.Unmarshal(&c)
	if err != nil {
		return nil, err
	}

	err = c.setup()
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// setup performs validation and setup.
func (c *Config) setup() error {
	// Check for showstopper errors
	if len(c.Secret) == 0 {
		return errors.New("\"secret\" option must be set")
	}

	// Field transformations
	c.secretBytes = []byte(c.Secret)
	if len(c.CallbackPath) > 0 && c.CallbackPath[0] != '/' {
		c.CallbackPath = "/" + c.CallbackPath
	}
	c.lifetimeDuration = time.Second * time.Duration(c.Lifetime)

	if err := c.parseTrustedNetworks(); err != nil {
		return err
	}

	// Add default rules
	if c.Rules == nil {
		c.Rules = make(map[string]*Rule)
	}
	if _, ok := c.Rules["default"]; !ok {
		c.Rules["default"] = &Rule{
			Action:    "auth",
			RouteRule: "",
			Priority:  -10000,
			AuthRule:  "",
		}
	}
	if _, ok := c.Rules["callback"]; !ok {
		c.Rules["callback"] = &Rule{
			Action:    "callback",
			RouteRule: fmt.Sprintf("Path(`%s`)", c.CallbackPath),
			Priority:  1,
			AuthRule:  "",
		}
	}
	if _, ok := c.Rules["health"]; !ok {
		c.Rules["health"] = &Rule{
			Action: "health",
			// No overlay
			RouteRule: "!HeaderRegexp(`X-Forwarded-Host`, `.+`) && Path(`/healthz`)",
			Priority:  1,
			AuthRule:  "",
		}
	}

	// Auth host check
	if c.AuthHost != "" {
		match, _ := c.matchCookieDomains(c.AuthHost)
		if !match {
			return errors.New("\"auth-host\" option must match one of \"cookie-domains\"")
		}
	}

	// Setup provider
	err := c.setupProvider(c.Provider)
	if err != nil {
		return err
	}

	// Setup rules and corresponding providers
	for _, rule := range c.Rules {
		err = rule.setup(c)
		if err != nil {
			return err
		}
	}

	// Setup header rules
	for _, h := range c.Headers {
		err = h.setup(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) parseTrustedNetworks() error {
	c.trustedIPNetworks = make([]*net.IPNet, len(c.TrustedIPAddresses))

	for i := range c.TrustedIPAddresses {
		addr := c.TrustedIPAddresses[i]
		if strings.Contains(addr, "/") {
			_, network, err := net.ParseCIDR(addr)
			if err != nil {
				return err
			}
			c.trustedIPNetworks[i] = network
			continue
		}

		ipAddr := net.ParseIP(addr)
		if ipAddr == nil {
			return fmt.Errorf("invalid ip address: '%s'", ipAddr)
		}

		c.trustedIPNetworks[i] = &net.IPNet{
			IP:   ipAddr,
			Mask: []byte{255, 255, 255, 255},
		}
	}

	return nil
}

// GetProvider returns the provider of the given name, if it has been selected.
// Returns an error if the provider is unknown, or hasn't been selected.
func (c *Config) GetProvider(name string) (provider.Provider, error) {
	if !c.isSelectedProvider(name) {
		return nil, fmt.Errorf("unconfigured provider: %s", name)
	}

	switch name {
	case "google":
		return &c.Providers.Google, nil
	case "oidc":
		return &c.Providers.OIDC, nil
	case "generic-oauth":
		return &c.Providers.GenericOAuth, nil
	}

	return nil, fmt.Errorf("unknown provider: %s", name)
}

func (c *Config) isSelectedProvider(name string) bool {
	return name == c.Provider
}

func (c *Config) setupProvider(name string) error {
	// Check provider exists
	p, err := c.GetProvider(name)
	if err != nil {
		return err
	}

	// Setup
	if err := p.Setup(); err != nil {
		return err
	}

	return nil
}

func (c *Config) IsIPAddressAuthenticated(address string) (bool, error) {
	addr := net.ParseIP(address)
	if addr == nil {
		return false, fmt.Errorf("invalid ip address: '%s'", address)
	}

	for _, n := range c.trustedIPNetworks {
		if n.Contains(addr) {
			return true, nil
		}
	}

	return false, nil
}

// Rule holds defined rules
type Rule struct {
	// Action defines auth action to take no this route.
	// 	Allowed values: "allow", "soft-auth", "allow", "login", "logout", "callback", "health"
	Action string `mapstructure:"action"`
	// RouteRule defines router rule to determine which request matches this rule.
	// Uses traefik v3 router syntax.
	// https://doc.traefik.io/traefik/routing/routers/
	//
	// Defaults to: PathPrefix(`/`). (catch-all)
	RouteRule string `mapstructure:"route-rule"`
	// Priority defines router rule priority.
	// Same rule as traefik v3 router applies.
	// Note that 0 means the default, len(RouteRule).
	Priority int `mapstructure:"priority"`
	// AuthRule defines whether a user is allowed to pass *after* authenticating the user.
	// Headers will be set *only when* this AuthRule passes.
	//
	// Similar syntax with traefik v3 router applies, but with different functions:
	//
	// 	- True() : Always passes.
	// 	- In(`path`, `value1`, `value2`, ...) : Passes when the userinfo is one of the values.
	// 	- Regexp(`path`, `pattern`) : Passes when the userinfo matches the pattern.
	//
	// "path" indicates dot notation path of userinfo object, retrieved via a provider.
	//
	// Example: Regexp(`email`, `^.+@example.com$`) && !In(`id`, `not-allowed-user`)
	//
	// Defaults to: True(). (pass-all)
	AuthRule string `mapstructure:"auth-rule"`
}

// setup performs validation and setup.
func (r *Rule) setup(c *Config) error {
	allowed := []string{"auth", "soft-auth", "allow", "login", "logout", "callback", "health"}
	if !lo.Contains(allowed, r.Action) {
		return fmt.Errorf("invalid rule action, must be one of: %v", allowed)
	}

	// Set defaults (catch-all)
	if r.RouteRule == "" {
		r.RouteRule = "PathPrefix(`/`)"
	}
	if r.AuthRule == "" {
		r.AuthRule = "True()"
	}

	// Validate rules
	// Ensure it's not referring to non-existent keys from generated token
	_, err := authrule.NewAuthRule(r.AuthRule, c.InfoFields)
	if err != nil {
		return err
	}

	return nil
}

type Header struct {
	// Name defines header name to pass extracted value to.
	Name string `mapstructure:"name"`
	// Source is dot notation path within userinfo object to extract value from. Nested value can be accessed via dot-separated key.
	Source string `mapstructure:"source"`
}

// setup performs validation.
func (h *Header) setup(c *Config) error {
	if h.Name == "" {
		return errors.New("header \"name\" must be set")
	}
	if h.Source == "" {
		return errors.New("header value \"source\" must be set")
	}
	// Ensure it's not referring to non-existent keys from generated token
	if !lo.Contains(c.InfoFields, h.Source) {
		return fmt.Errorf("source \"%v\" of header \"%v\" is not going to be included in generated tokens - include it in \"info-fields\" config", h.Source, h.Name)
	}
	return nil
}
