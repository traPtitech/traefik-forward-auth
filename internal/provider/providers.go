package provider

import (
	"context"
	// "net/url"

	"golang.org/x/oauth2"
)

// Providers contains all the implemented providers
type Providers struct {
	Google       Google       `mapstructure:"google"`
	OIDC         OIDC         `mapstructure:"oidc"`
	GenericOAuth GenericOAuth `mapstructure:"generic-oauth"`
}

// Provider is used to authenticate users
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string, allowPrompt bool) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token string) (any, error)
	Setup() error
}

type token struct {
	Token string `json:"access_token"`
}

// OAuthProvider is a provider using the oauth2 library
type OAuthProvider struct {
	Scopes   []string `mapstructure:"scopes"`
	Prompt   string   `mapstructure:"prompt"`
	Resource string   `mapstructure:"resource"`

	Config *oauth2.Config
	ctx    context.Context
}

// ConfigCopy returns a copy of the oauth2 config with the given redirectURI
// which ensures the underlying config is not modified
func (p *OAuthProvider) ConfigCopy(redirectURI string) oauth2.Config {
	config := *p.Config
	config.RedirectURL = redirectURI
	return config
}

// OAuthGetLoginURL provides a base "GetLoginURL" for proiders using OAauth2
func (p *OAuthProvider) OAuthGetLoginURL(redirectURI, state string, allowPrompt bool) string {
	config := p.ConfigCopy(redirectURI)

	var options []oauth2.AuthCodeOption
	if p.Prompt != "" && allowPrompt {
		options = append(options, oauth2.SetAuthURLParam("prompt", p.Prompt))
	}
	if p.Resource != "" {
		options = append(options, oauth2.SetAuthURLParam("resource", p.Resource))
	}

	return config.AuthCodeURL(state, options...)
}

// OAuthExchangeCode provides a base "ExchangeCode" for proiders using OAauth2
func (p *OAuthProvider) OAuthExchangeCode(redirectURI, code string) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectURI)
	return config.Exchange(p.ctx, code)
}
