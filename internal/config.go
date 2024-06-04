package tfa

import (
	"errors"
	"fmt"
	"github.com/spf13/viper"
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
	// DefaultAction defines default action for providers.
	DefaultAction string `mapstructure:"default-action"`
	// DefaultProvider defines default provider.
	// 	Allowed values: "google", "oidc", "generic-oauth"
	DefaultProvider string `mapstructure:"default-provider"`
	// Domains defines to only allow given email domains. Comma separated.
	Domains []string `mapstructure:"domains"`
	// HeaderNames define user header names. Comma separated.
	HeaderNames []string `mapstructure:"header-names"`
	// Lifetime defines cookie lifetime in seconds.
	Lifetime int `mapstructure:"lifetime"`
	// MatchWhitelistOrDomain allows users that match *either* whitelist or domain.
	MatchWhitelistOrDomain bool `mapstructure:"match-whitelist-or-domain"`
	// URLPath defines callback URL path.
	URLPath string `mapstructure:"url-path"`
	// Secret defines secret used for signing (required).
	Secret string `mapstructure:"secret"`
	// SoftAuthUser defines username used in header if unauthorized with soft-auth action.
	SoftAuthUser string `mapstructure:"soft-auth-user"`
	// UserIDPath is dot notation path of a UserID for use with whitelist and user header names (default: X-Forwarded-Auth).
	UserIDPath string `mapstructure:"user-id-path"`
	// Whitelist only allows given UserID. Comma separated.
	Whitelist []string `mapstructure:"whitelist"`
	// TrustedIPAddresses define list of trusted IP addresses or IP networks (in CIDR notation) that are considered authenticated. Comma separated.
	TrustedIPAddresses []string `mapstructure:"trusted-ip-addresses"`
	// Port defines port to listen on.
	Port int `mapstructure:"port"`

	Providers provider.Providers `mapstructure:"providers"`
	Rules     map[string]*Rule   `mapstructure:"rules"`

	// Filled during transformations
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
	viper.SetDefault("default-action", "auth")
	viper.SetDefault("default-provider", "google")
	viper.SetDefault("header-names", "X-Forwarded-User")
	viper.SetDefault("lifetime", "43200")
	viper.SetDefault("url-path", "/_oauth")
	viper.SetDefault("user-id-path", "email")
	viper.SetDefault("port", "4181")

	viper.SetDefault("providers.google.prompt", "select_account")
	viper.SetDefault("providers.oidc.scopes", "profile,email")
	viper.SetDefault("providers.generic-oauth.token-style", "header")
	viper.SetDefault("providers.generic-oauth.scopes", "profile,email")
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
	if len(c.HeaderNames) == 0 {
		return errors.New("\"header-names\" option must be set")
	}

	// Field transformations
	if len(c.URLPath) > 0 && c.URLPath[0] != '/' {
		c.URLPath = "/" + c.URLPath
	}
	c.lifetimeDuration = time.Second * time.Duration(c.Lifetime)

	if err := c.parseTrustedNetworks(); err != nil {
		return err
	}

	// Setup default provider
	err := c.setupProvider(c.DefaultProvider)
	if err != nil {
		return err
	}

	// Setup rules and corresponding providers
	for _, rule := range c.Rules {
		err = rule.Setup(c)
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

// GetProvider returns the provider of the given name, if it has been
// configured. Returns an error if the provider is unknown, or hasn't been configured
func (c *Config) GetProvider(name string) (provider.Provider, error) {
	// Check the provider has been configured
	if !c.isProviderConfigured(name) {
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

func (c *Config) isProviderConfigured(name string) bool {
	// Check default provider
	if name == c.DefaultProvider {
		return true
	}

	// Check rule providers
	for _, rule := range c.Rules {
		if name == rule.Provider {
			return true
		}
	}

	return false
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

// Rule holds defined rules
type Rule struct {
	Action    string   `mapstructure:"action"`
	Rule      string   `mapstructure:"rule"`
	Provider  string   `mapstructure:"provider"`
	Whitelist []string `mapstructure:"whitelist"`
	Domains   []string `mapstructure:"domains"`
}

// NewRule creates a new rule object
func NewRule() *Rule {
	return &Rule{
		Action: "auth",
	}
}

// Setup performs validation and setup.
func (r *Rule) Setup(c *Config) error {
	if r.Action != "auth" && r.Action != "soft-auth" && r.Action != "allow" {
		return errors.New("invalid rule action, must be \"auth\", \"soft-auth\", or \"allow\"")
	}

	// Set default provider on any rules where it's not specified
	if r.Provider == "" {
		r.Provider = c.DefaultProvider
	}

	return c.setupProvider(r.Provider)
}
