package tfa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func signature(user, expireUnixSecond string) string {
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(user))
	hash.Write([]byte(expireUnixSecond))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// token signs a new token for recording this authentication.
//
// A token consists of three parts:
// - Signature = HMAC256(key = secret, data = user + expireUnixSecond)
// - Expiry in unix timestamp (seconds)
// - Username
//
// These parts are concatenated with a vertical bar '|' to make up a single token.
func token(user string, expireUnixSecond int64) string {
	mac := signature(user, fmt.Sprintf("%d", expireUnixSecond))
	return fmt.Sprintf("%s|%d|%s", mac, expireUnixSecond, user)
}

func verifyToken(token string) (string, error) {
	parts := strings.Split(token, "|")

	if len(parts) != 3 {
		return "", errors.New("Invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Unable to decode cookie mac")
	}

	expectedSignature := signature(parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("Unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", ErrInvalidSignature
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("Unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", ErrCookieExpired
	}

	// Looks valid
	return parts[2], nil
}
