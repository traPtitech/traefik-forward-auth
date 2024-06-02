package tfa

import (
	"testing"
	"time"
)

const (
	testSecret = "SLUGoz2n44q2Wh-dQRXe-IheSpjfcBzy"
	testUser   = "test-user"
)

func BenchmarkVerifyToken_Original(b *testing.B) {
	config.Secret = []byte(testSecret)

	expiry := time.Now().Unix() + 100
	tok := token(testUser, expiry)

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

func BenchmarkVerifyToken_JWT(b *testing.B) {
	// TODO?
}
