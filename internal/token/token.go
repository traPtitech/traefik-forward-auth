package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/golang-jwt/jwt/v5"
)

const userinfoKey = "tfa"

const (
	claimKind     = "typ"
	claimUser     = "usr"
	claimNonce    = "nonce"
	claimRedirect = "rd"

	kindHost   = "host"
	kindTicket = "ticket"
)

var (
	// ErrKind is returned when a token of another kind is presented, e.g. a ticket in place of a host token.
	ErrKind = errors.New("unexpected token kind")
	// ErrAudience is returned when a token issued for another host is presented.
	ErrAudience = errors.New("token issued for another host")
	// ErrExpired is returned when an expired token is presented.
	ErrExpired = errors.New("token expired")
)

func GetPathStr(object any, path string) (s string, ok bool) {
	obj := gabs.Wrap(object)
	if !obj.ExistsP(path) {
		return "", false
	}
	return fmt.Sprintf("%v", obj.Path(path).Data()), true
}

func LimitFields(object any, fields []string) (any, error) {
	source := gabs.Wrap(object)
	target := gabs.New()
	var err error
	for _, field := range fields {
		if !source.ExistsP(field) {
			return nil, fmt.Errorf("field %v not found in userinfo", field)
		}
		v := fmt.Sprintf("%v", source.Path(field).Data())
		_, err = target.SetP(v, field)
		if err != nil {
			return nil, err
		}
	}
	return target.Data(), nil
}

// SignHostToken signs a token that authenticates the user only on the host aud.
func SignHostToken(user any, aud string, expiry time.Time, secret []byte) (string, error) {
	return sign(jwt.MapClaims{
		claimKind: kindHost,
		"aud":     aud,
		"exp":     expiry.Unix(),
		claimUser: user,
	}, secret)
}

// VerifyHostToken returns the user of a host token issued for the host aud.
// It fails with ErrKind for tokens of other kinds, ErrAudience for tokens of other hosts,
// ErrExpired for expired tokens, and other errors for malformed tokens or bad signatures.
func VerifyHostToken(tok, aud string, secret []byte) (any, error) {
	claims, err := verify(tok, aud, kindHost, secret)
	if err != nil {
		return nil, err
	}
	user, ok := claims[claimUser]
	if !ok {
		return nil, errors.New("user claim not found")
	}
	return user, nil
}

// Ticket is the content of a ticket, which hands over an authenticated user from the auth host to the host aud.
type Ticket struct {
	User any
	// NonceHash is the hex-encoded SHA-256 of the nonce cookie that the receiving host set when it started the login.
	// Callers must compare it against the nonce cookie; VerifyTicket does not.
	NonceHash string
	// Redirect is the URL on the receiving host to return to after the ticket is exchanged.
	Redirect string
}

// SignTicket signs a ticket for the host aud.
func SignTicket(t Ticket, aud string, expiry time.Time, secret []byte) (string, error) {
	return sign(jwt.MapClaims{
		claimKind:     kindTicket,
		"aud":         aud,
		"exp":         expiry.Unix(),
		claimUser:     t.User,
		claimNonce:    t.NonceHash,
		claimRedirect: t.Redirect,
	}, secret)
}

// VerifyTicket verifies the signature, kind, audience and expiry of a ticket, failing with the same errors as VerifyHostToken.
// It does not check the nonce; see Ticket.NonceHash.
func VerifyTicket(tok, aud string, secret []byte) (Ticket, error) {
	claims, err := verify(tok, aud, kindTicket, secret)
	if err != nil {
		return Ticket{}, err
	}
	user, ok := claims[claimUser]
	if !ok {
		return Ticket{}, errors.New("user claim not found")
	}
	nonceHash, ok := claims[claimNonce].(string)
	if !ok || nonceHash == "" {
		return Ticket{}, errors.New("nonce claim not found")
	}
	redirect, ok := claims[claimRedirect].(string)
	if !ok || redirect == "" {
		return Ticket{}, errors.New("redirect claim not found")
	}
	return Ticket{User: user, NonceHash: nonceHash, Redirect: redirect}, nil
}

func sign(claims jwt.MapClaims, secret []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func verify(tok, aud, kind string, secret []byte) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(aud),
	)
	parsed, err := parser.Parse(tok, func(*jwt.Token) (any, error) { return secret, nil })
	switch {
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return nil, fmt.Errorf("%w: %w", ErrAudience, err)
	case errors.Is(err, jwt.ErrTokenExpired):
		return nil, fmt.Errorf("%w: %w", ErrExpired, err)
	case err != nil:
		return nil, err
	}
	if !parsed.Valid { // should be unreachable, but check the field just in case
		return nil, errors.New("invalid token")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims[claimKind] != kind {
		return nil, ErrKind
	}
	return claims, nil
}

// SignToken signs a new token for recording this authentication.
func SignToken(object any, expiryUnixSeconds int64, secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"exp":       expiryUnixSeconds,
		userinfoKey: object,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

var jwtParser = jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

func VerifyToken(token string, secret []byte) (any, error) {
	tok, err := jwtParser.Parse(token, func(token *jwt.Token) (any, error) { return secret, nil })
	if err != nil {
		return "", err
	}
	if !tok.Valid { // should be unreachable, but check the field just in case
		return "", errors.New("invalid token")
	}
	mc := tok.Claims.(jwt.MapClaims)
	object, ok := mc[userinfoKey]
	if !ok {
		return "", errors.New("tfa field not found")
	}
	return object, nil
}
