package tfa

import (
	"github.com/samber/lo"
	// "fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/**
 * Tests
 */

func prepareTmpFile(pattern string, content string) (path string) {
	tmpFile := lo.Must(os.CreateTemp("", pattern))
	lo.Must(tmpFile.WriteString(content))
	lo.Must0(tmpFile.Close())
	return tmpFile.Name()
}

func TestConfigDefaults(t *testing.T) {
	assert := assert.New(t)

	const leastValidConfig = `
secret: very-secret
providers:
  google:
    client-id: id
    client-secret: secret`
	tmpConfigFile := prepareTmpFile("*.yaml", leastValidConfig)
	c, err := NewConfig(tmpConfigFile)
	assert.NoError(err)

	assert.Equal("warn", c.LogLevel)
	assert.Equal("text", c.LogFormat)

	assert.Equal("", c.AuthHost)
	assert.Len(c.CookieDomains, 0)
	assert.False(c.InsecureCookie)
	assert.Equal("_forward_auth", c.CookieName)
	assert.Equal("_forward_auth_csrf", c.CSRFCookieName)
	assert.Equal("auth", c.DefaultAction)
	assert.Equal("google", c.DefaultProvider)
	assert.Len(c.Domains, 0)
	assert.Equal([]string{"X-Forwarded-User"}, c.HeaderNames)
	assert.Equal(time.Second*time.Duration(43200), c.lifetimeDuration)
	assert.False(c.MatchWhitelistOrDomain)
	assert.Equal("/_oauth", c.URLPath)
	assert.Equal("", c.SoftAuthUser)
	assert.Len(c.Whitelist, 0)
	assert.Equal(c.Port, 4181)

	assert.Equal("select_account", c.Providers.Google.Prompt)

	assert.Len(c.TrustedIPAddresses, 0)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)

	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: very-secret
providers:
  google:
    client-id: id
    client-secret: secret

cookie-name: cookiename
csrf-cookie-name: csrfcookiename
port: 8000

rules:
  "1":
    action: allow
    rule: `+"PathPrefix(`/one`)"+`
  two:
    action: auth
    rule: `+"Host(`two.com`) && Path(`/two`)"+`
`)
	c, err := NewConfig(tmpConfigFile)
	require.Nil(t, err)

	// Check normal flags
	assert.Equal("cookiename", c.CookieName)
	assert.Equal("csrfcookiename", c.CSRFCookieName)
	assert.Equal(8000, c.Port)

	// Check rules
	assert.Equal(map[string]*Rule{
		"1": {
			Action:   "allow",
			Rule:     "PathPrefix(`/one`)",
			Provider: "google",
		},
		"two": {
			Action:   "auth",
			Rule:     "Host(`two.com`) && Path(`/two`)",
			Provider: "google",
		},
	}, c.Rules)
}

func TestConfigParseUnknownFlags(t *testing.T) {
	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: very-secret
providers:
  google:
    client-id: id
    client-secret: secret
unknown: _oauthPath2`)
	_, err := NewConfig(tmpConfigFile)
	assert.NoError(t, err) // No error on unknown config elements
}

func TestConfigCommaSeperated(t *testing.T) {
	assert := assert.New(t)

	c := initTestConfig()
	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: very-secret
providers:
  google:
    client-id: id
    client-secret: secret
whitelist: test@test.com,test2@test2.com`)
	c, err := NewConfig(tmpConfigFile)
	require.Nil(t, err)

	expected1 := []string{"test@test.com", "test2@test2.com"}
	assert.Equal(expected1, c.Whitelist, "should read legacy comma separated list whitelist")
}

func TestConfigParseYaml(t *testing.T) {
	assert := assert.New(t)

	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: very-secret
providers:
  google:
    client-id: id
    client-secret: secret

cookie-name: yamlcookiename
csrf-cookie-name: yamlcsrfcookiename
url-path: one

rules:
  "1":
    action: allow
    rule: `+"PathPrefix(`/one`)"+`
  two:
    action: auth
    rule: `+"Host(`two.com`) && Path(`/two`)"+`
`)
	c, err := NewConfig(tmpConfigFile)
	require.Nil(t, err)

	assert.Equal("yamlcookiename", c.CookieName, "should be read from yaml file")
	assert.Equal("yamlcsrfcookiename", c.CSRFCookieName, "should be read from yaml file")
	assert.Equal(map[string]*Rule{
		"1": {
			Action:   "allow",
			Rule:     "PathPrefix(`/one`)",
			Provider: "google",
		},
		"two": {
			Action:   "auth",
			Rule:     "Host(`two.com`) && Path(`/two`)",
			Provider: "google",
		},
	}, c.Rules)
}

func TestConfigParseEnvironment(t *testing.T) {
	// NOTE: As of github.com/spf13/viper@v1.19.0, this behavior requires "viper_bind_struct" build tag to work.
	// Otherwise, keys not explicitly registered to viper (except the very existence of struct fields) will not be
	// returned by viper.AllKeys(), and they will not be looked up on unmarshalling.

	assert := assert.New(t)
	t.Setenv("SECRET", "super-secret")
	t.Setenv("COOKIE_NAME", "env_cookie_name")
	t.Setenv("PROVIDERS_GOOGLE_CLIENT_ID", "env_client_id")
	t.Setenv("PROVIDERS_GOOGLE_CLIENT_SECRET", "very-secret")
	t.Setenv("COOKIE_DOMAINS", "test1.com,example.org")
	t.Setenv("DOMAINS", "test2.com,example.org")
	t.Setenv("WHITELIST", "test3.com,example.org")

	require.Equal(t, "env_cookie_name", os.Getenv("COOKIE_NAME"))

	c, err := NewConfig("")
	require.Nil(t, err)

	assert.Equal("super-secret", c.Secret, "variable should be read from environment")
	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")
	assert.Equal("env_client_id", c.Providers.Google.ClientID, "variable should be read from environment")
	assert.Equal("very-secret", c.Providers.Google.ClientSecret, "variable should be read from environment")
	assert.Equal([]CookieDomain{
		"test1.com",
		"example.org",
	}, c.CookieDomains, "array variable should be read from environment COOKIE_DOMAINS")
	assert.Equal([]string{"test2.com", "example.org"}, c.Domains, "array variable should be read from environment DOMAINS")
	assert.Equal([]string{"test3.com", "example.org"}, c.Whitelist, "array variable should be read from environment WHITELIST")
}

func TestConfigTransformation(t *testing.T) {
	assert := assert.New(t)

	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: verysecret
providers:
  google:
    client-id: id
    client-secret: secret
url-path: _oauthpath
lifetime: 200
`)
	c, err := NewConfig(tmpConfigFile)
	require.Nil(t, err)

	assert.Equal("/_oauthpath", c.URLPath, "path should add slash to front")

	assert.Equal("verysecret", c.Secret)

	assert.Equal(200, c.Lifetime)
	assert.Equal(time.Second*time.Duration(200), c.lifetimeDuration, "lifetime should be read and converted to duration")
}

func TestConfigValidate(t *testing.T) {
	t.Run("missing secret", func(t *testing.T) {
		tmpConfigFile := prepareTmpFile("*.yaml", `
providers:
  google:
    client-id: id
    client-secret: secret
rules:
  "1":
    action: auth
`)
		_, err := NewConfig(tmpConfigFile)
		assert.Error(t, err)
		assert.Equal(t, "\"secret\" option must be set", err.Error())
	})

	t.Run("default provider option not set", func(t *testing.T) {
		tmpConfigFile := prepareTmpFile("*.yaml", `
secret: secret
rules:
  "1":
    action: auth
`)
		_, err := NewConfig(tmpConfigFile)
		assert.Error(t, err)
		assert.Equal(t, "providers.google.client-id, providers.google.client-secret must be set", err.Error())
	})

	t.Run("invalid rule action", func(t *testing.T) {
		tmpConfigFile := prepareTmpFile("*.yaml", `
secret: secret
providers:
  google:
    client-id: id
    client-secret: secret
rules:
  "1":
    action: bad
`)
		_, err := NewConfig(tmpConfigFile)
		assert.Error(t, err)
		assert.Equal(t, "invalid rule action, must be \"auth\", \"soft-auth\", or \"allow\"", err.Error())
	})

	t.Run("invalid rule provider", func(t *testing.T) {
		tmpConfigFile := prepareTmpFile("*.yaml", `
secret: secret
providers:
  google:
    client-id: id
    client-secret: secret
rules:
  "1":
    action: auth
    provider: bad2
`)
		_, err := NewConfig(tmpConfigFile)
		assert.Error(t, err)
		assert.Equal(t, "unknown provider: bad2", err.Error())
	})
}

func TestConfigGetProvider(t *testing.T) {
	assert := assert.New(t)
	c := initTestConfig()

	// Should be able to get "google" default provider
	p, err := c.GetProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	// Should fail to get valid "oidc" provider as it's not configured
	p, err = c.GetProvider("oidc")
	if assert.Error(err) {
		assert.Equal("unconfigured provider: oidc", err.Error())
	}

	// Should catch unknown provider
	p, err = c.GetProvider("bad")
	if assert.Error(err) {
		assert.Equal("unconfigured provider: bad", err.Error())
	}
}

func TestConfigTrustedNetworks(t *testing.T) {
	assert := assert.New(t)

	tmpConfigFile := prepareTmpFile("*.yaml", `
secret: secret
providers:
  google:
    client-id: id
    client-secret: secret
trusted-ip-addresses:
  - 1.2.3.4
  - 30.1.0.0/16
`)
	c, err := NewConfig(tmpConfigFile)
	assert.NoError(err)

	table := map[string]bool{
		"1.2.3.3":      false,
		"1.2.3.4":      true,
		"1.2.3.5":      false,
		"192.168.1.1":  false,
		"30.1.0.1":     true,
		"30.1.255.254": true,
		"30.2.0.1":     false,
	}

	for in, want := range table {
		got, err := c.IsIPAddressAuthenticated(in)
		assert.NoError(err)
		assert.Equal(want, got, "ip address: %s", in)
	}
}
