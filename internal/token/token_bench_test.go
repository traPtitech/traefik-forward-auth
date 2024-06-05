// Below contains code for comparison with traefik-forward-auth original and JWT-based token implementation.
// JWT-based impl. is about 3~4 times slower than the original HMAC256-based implementation.
//
// Despite the slowdown, JWT specification and its library allows ease addition of new fields into the token.
// So JWT is more suitable for dynamic header fields configuration, while the performance degradation remains
// acceptable if HMAC-based signing is used.
// (As a bonus, it also comes with specific prefix and format for easier credentials scanning.)

package token_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/samber/lo"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "SLUGoz2n44q2Wh-dQRXe-IheSpjfcBzy"
	testUser   = "test-user"
)

var testSecretB = []byte(testSecret)

func signature(user, expireUnixSecond string) string {
	hash := hmac.New(sha256.New, testSecretB)
	hash.Write([]byte(user))
	hash.Write([]byte(expireUnixSecond))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

func SignToken(user string, expireUnixSecond int64) string {
	mac := signature(user, fmt.Sprintf("%d", expireUnixSecond))
	return fmt.Sprintf("%s|%d|%s", mac, expireUnixSecond, user)
}

func verifyToken(token string) (string, error) {
	parts := strings.Split(token, "|")

	if len(parts) != 3 {
		return "", errors.New("invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("unable to decode cookie mac")
	}

	expectedSignature := signature(parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New("invalid mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("token expired")
	}

	// Looks valid
	return parts[2], nil
}

func BenchmarkSignToken_Original(b *testing.B) {
	expiry := time.Now().Unix() + 100

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_ = SignToken(testUser, expiry)
	}
}

func BenchmarkVerifyToken_Original(b *testing.B) {
	expiry := time.Now().Unix() + 100
	tok := SignToken(testUser, expiry)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		verifiedUser, err := verifyToken(tok)
		if err != nil {
			b.Fatal(err)
		}
		if verifiedUser != testUser {
			b.Fatal("verified user is wrong")
		}
	}
}

func signJWT(user string, expiry int64) string {
	claims := jwt.MapClaims{
		"exp": expiry,
		"sub": user,
	}
	return lo.Must(jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(testSecretB))
}

func verifyJWT(token string) (string, error) {
	tok := lo.Must(jwt.Parse(token, func(token *jwt.Token) (any, error) { return testSecretB, nil }))
	return tok.Claims.GetSubject()
}

func BenchmarkSignToken_JWT(b *testing.B) {
	expiry := time.Now().Unix() + 100

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_ = signJWT(testUser, expiry)
	}
}

func BenchmarkVerifyToken_JWT(b *testing.B) {
	expiry := time.Now().Unix() + 100
	tok := signJWT(testUser, expiry)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		verifiedUser, err := verifyJWT(tok)
		if err != nil {
			b.Fatal(err)
		}
		if verifiedUser != testUser {
			b.Fatal("verified user is wrong")
		}
	}
}
