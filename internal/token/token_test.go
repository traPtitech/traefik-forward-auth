package token

import (
	"bytes"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

type m = map[string]any

func TestGetPathStr(t *testing.T) {
	userinfo := m{
		"username": "test-user",
		"nested": m{
			"key": "value",
		},
	}

	v, ok := GetPathStr(userinfo, "username")
	assert.True(t, ok)
	assert.Equal(t, "test-user", v)

	v, ok = GetPathStr(userinfo, "nested.key")
	assert.True(t, ok)
	assert.Equal(t, "value", v)

	v, ok = GetPathStr(userinfo, "non-existent")
	assert.False(t, ok)
}

func TestLimitFields(t *testing.T) {
	userinfo := m{
		"username":   "test-user",
		"additional": "info",
		"nested": m{
			"key-1": "value-1",
			"key-2": "value-2",
		},
	}

	t.Run("success", func(t *testing.T) {
		result, err := LimitFields(userinfo, []string{"username", "nested.key-1"})
		require.NoError(t, err)
		assert.Equal(t, m{
			"username": "test-user",
			"nested": m{
				"key-1": "value-1",
			},
		}, result)
	})

	t.Run("missing fields", func(t *testing.T) {
		_, err := LimitFields(userinfo, []string{"id", "nested.key-1"})
		assert.Error(t, err)
	})
}

func TestVerifyHostToken(t *testing.T) {
	secret := []byte("secret")
	userinfo := m{
		"username": "test-user",
		"nested": m{
			"key": "value",
		},
	}
	valid := time.Now().Add(10 * time.Second)

	t.Run("should not pass empty", func(t *testing.T) {
		_, err := VerifyHostToken("", "app.example.com", secret)
		assert.Error(t, err)
	})

	t.Run("should not pass 'none' algorithm", func(t *testing.T) {
		claims := jwt.MapClaims{
			claimKind: kindHost,
			"aud":     "app.example.com",
			"exp":     valid.Unix(),
			claimUser: m{},
		}
		tokenString, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		_, err = VerifyHostToken(tokenString, "app.example.com", secret)
		assert.Error(t, err)
	})

	t.Run("should catch modified mac", func(t *testing.T) {
		tok, err := SignHostToken(userinfo, "app.example.com", valid, secret)
		require.NoError(t, err)

		tokBytes := []byte(tok)
		idx := bytes.LastIndex(tokBytes, []byte{'.'})
		tokBytes[idx+1] = lo.Ternary(tokBytes[idx+1] == 'A', byte('B'), byte('A'))

		_, err = VerifyHostToken(string(tokBytes), "app.example.com", secret)
		assert.Error(t, err)
	})

	t.Run("should catch expired", func(t *testing.T) {
		tok, err := SignHostToken(userinfo, "app.example.com", time.Now().Add(-time.Second), secret)
		require.NoError(t, err)

		_, err = VerifyHostToken(tok, "app.example.com", secret)
		assert.ErrorIs(t, err, ErrExpired)
	})

	t.Run("should reject token for another host", func(t *testing.T) {
		tok, err := SignHostToken(userinfo, "evil.example.com", valid, secret)
		require.NoError(t, err)

		_, err = VerifyHostToken(tok, "app.example.com", secret)
		assert.ErrorIs(t, err, ErrAudience)
	})

	t.Run("should reject ticket", func(t *testing.T) {
		tok, err := SignTicket(Ticket{User: userinfo, NonceHash: "hash", Redirect: "https://app.example.com/"}, "app.example.com", valid, secret)
		require.NoError(t, err)

		_, err = VerifyHostToken(tok, "app.example.com", secret)
		assert.ErrorIs(t, err, ErrKind)
	})

	// Tokens of the previous format carry no audience and must not be accepted after migration.
	t.Run("should reject token without audience", func(t *testing.T) {
		tok, err := sign(jwt.MapClaims{"exp": valid.Unix(), "tfa": userinfo}, secret)
		require.NoError(t, err)

		_, err = VerifyHostToken(tok, "app.example.com", secret)
		assert.Error(t, err)
	})

	t.Run("should accept valid token", func(t *testing.T) {
		tok, err := SignHostToken(userinfo, "app.example.com", valid, secret)
		require.NoError(t, err)

		object, err := VerifyHostToken(tok, "app.example.com", secret)
		assert.NoError(t, err)
		assert.Equal(t, userinfo, object)
	})
}

func TestVerifyTicket(t *testing.T) {
	secret := []byte("secret")
	userinfo := m{"username": "test-user"}
	ticket := Ticket{User: userinfo, NonceHash: "hash", Redirect: "https://app.example.com/page"}
	valid := time.Now().Add(10 * time.Second)

	t.Run("should accept valid ticket", func(t *testing.T) {
		tok, err := SignTicket(ticket, "app.example.com", valid, secret)
		require.NoError(t, err)

		got, err := VerifyTicket(tok, "app.example.com", secret)
		assert.NoError(t, err)
		assert.Equal(t, ticket, got)
	})

	t.Run("should reject ticket for another host", func(t *testing.T) {
		tok, err := SignTicket(ticket, "evil.example.com", valid, secret)
		require.NoError(t, err)

		_, err = VerifyTicket(tok, "app.example.com", secret)
		assert.ErrorIs(t, err, ErrAudience)
	})

	t.Run("should reject expired ticket", func(t *testing.T) {
		tok, err := SignTicket(ticket, "app.example.com", time.Now().Add(-time.Second), secret)
		require.NoError(t, err)

		_, err = VerifyTicket(tok, "app.example.com", secret)
		assert.ErrorIs(t, err, ErrExpired)
	})

	t.Run("should reject host token", func(t *testing.T) {
		tok, err := SignHostToken(userinfo, "app.example.com", valid, secret)
		require.NoError(t, err)

		_, err = VerifyTicket(tok, "app.example.com", secret)
		assert.ErrorIs(t, err, ErrKind)
	})

	t.Run("should reject ticket without nonce", func(t *testing.T) {
		tok, err := SignTicket(Ticket{User: userinfo, Redirect: "https://app.example.com/"}, "app.example.com", valid, secret)
		require.NoError(t, err)

		_, err = VerifyTicket(tok, "app.example.com", secret)
		assert.Error(t, err)
	})
}

func Test_verifyToken(t *testing.T) {
	secret := []byte("secret")
	userinfo := m{
		"username": "test-user",
		"nested": m{
			"key": "value",
		},
	}

	t.Run("should not pass empty with default", func(t *testing.T) {
		assert := assert.New(t)

		_, err := VerifyToken("", secret)
		assert.Error(err)
	})

	t.Run("should not pass 'none' algorithm", func(t *testing.T) {
		assert := assert.New(t)

		expiry := time.Now().Add(10 * time.Second).Unix()
		claims := jwt.MapClaims{
			"exp":       expiry,
			userinfoKey: map[string]any{},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		_, err = VerifyToken(tokenString, secret)
		assert.Error(err)
	})

	t.Run("should catch modified mac", func(t *testing.T) {
		assert := assert.New(t)

		expiry := time.Now().Add(10 * time.Second).Unix()
		tok, err := SignToken(userinfo, expiry, secret)
		require.NoError(t, err)

		// Tamper with the signature
		tokBytes := []byte(tok)
		idx := bytes.LastIndex(tokBytes, []byte{'.'})
		tokBytes[idx+1] = lo.Ternary(tokBytes[idx+1] == 'A', byte('B'), byte('A'))

		_, err = VerifyToken(string(tokBytes), secret)
		assert.Error(err)
	})

	t.Run("should catch expired", func(t *testing.T) {
		assert := assert.New(t)

		expiry := time.Now().Add(-time.Second).Unix()
		tok, err := SignToken(userinfo, expiry, secret)
		require.NoError(t, err)

		_, err = VerifyToken(tok, secret)
		assert.Error(err)
	})

	t.Run("should accept valid cookie", func(t *testing.T) {
		assert := assert.New(t)

		expiry := time.Now().Add(10 * time.Second).Unix()
		tok, err := SignToken(userinfo, expiry, secret)
		require.NoError(t, err)

		object, err := VerifyToken(tok, secret)
		assert.Nil(err, "valid request should not return an error")
		assert.Equal(m{
			"username": "test-user",
			"nested": m{
				"key": "value",
			},
		}, object, "valid request should return user email")
	})
}
