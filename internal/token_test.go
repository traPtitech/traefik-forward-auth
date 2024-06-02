package tfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_verifyToken(t *testing.T) {
	t.Run("should not pass empty with default", func(t *testing.T) {
		assert := assert.New(t)
		config, _ = NewConfig([]string{""})

		_, err := verifyToken("")
		if assert.Error(err) {
			assert.Equal("Invalid cookie format", err.Error())
		}
	})

	t.Run("should require 3 parts", func(t *testing.T) {
		assert := assert.New(t)
		config, _ = NewConfig([]string{""})

		_, err := verifyToken("")
		if assert.Error(err) {
			assert.Equal("Invalid cookie format", err.Error())
		}
		_, err = verifyToken("1|2")
		if assert.Error(err) {
			assert.Equal("Invalid cookie format", err.Error())
		}
		_, err = verifyToken("1|2|3|4")
		if assert.Error(err) {
			assert.Equal("Invalid cookie format", err.Error())
		}
	})

	t.Run("should catch invalid mac", func(t *testing.T) {
		assert := assert.New(t)
		config, _ = NewConfig([]string{""})

		_, err := verifyToken("MQ==|2|3")
		if assert.Error(err) {
			assert.Equal(ErrInvalidSignature, err)
		}
	})

	t.Run("should catch expired", func(t *testing.T) {
		assert := assert.New(t)
		config, _ = NewConfig([]string{""})

		expiry := time.Now().Add(-time.Second).Unix()
		tok := token("test@test.com", expiry)

		_, err := verifyToken(tok)
		if assert.Error(err) {
			assert.Equal("Cookie has expired", err.Error())
		}
	})

	t.Run("should accept valid cookie", func(t *testing.T) {
		assert := assert.New(t)
		config, _ = NewConfig([]string{""})

		expiry := time.Now().Add(10 * time.Second).Unix()
		tok := token("test@test.com", expiry)

		email, err := verifyToken(tok)
		assert.Nil(err, "valid request should not return an error")
		assert.Equal("test@test.com", email, "valid request should return user email")
	})
}
