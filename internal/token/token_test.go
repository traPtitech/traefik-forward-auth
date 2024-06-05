package token

import (
	"bytes"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

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
