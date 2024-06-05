package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Google provider
type Google struct {
	ClientID     string `mapstructure:"client-id"`
	ClientSecret string `mapstructure:"client-secret"`
	// Scope defines list of requested scopes. Space separated.
	Scope string
	// Prompt defines list of OpenID prompt options. Space separated.
	Prompt string `mapstructure:"prompt"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

// Name returns the name of the provider
func (g *Google) Name() string {
	return "google"
}

// Setup performs validation and setup
func (g *Google) Setup() error {
	if g.ClientID == "" || g.ClientSecret == "" {
		return errors.New("providers.google.client-id, providers.google.client-secret must be set")
	}

	// Set static values
	g.Scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
	g.LoginURL = &url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
	}
	g.TokenURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v3/token",
	}
	g.UserURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v2/userinfo",
	}

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (g *Google) GetLoginURL(redirectURI, state string, forcePrompt bool) string {
	q := url.Values{}
	q.Set("client_id", g.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", g.Scope)
	if g.Prompt != "" {
		q.Set("prompt", g.Prompt)
	}
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	var u url.URL
	u = *g.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (g *Google) ExchangeCode(redirectURI, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.ClientID)
	form.Set("client_secret", g.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	res, err := http.PostForm(g.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

// GetUser uses the given token and returns a userID located at the json path
func (g *Google) GetUser(token string) (any, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var userinfo any
	err = json.NewDecoder(res.Body).Decode(&userinfo)
	if err != nil {
		return "", err
	}
	return userinfo, nil
}
