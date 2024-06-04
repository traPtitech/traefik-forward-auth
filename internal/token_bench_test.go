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
	config.Secret = testSecret

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

// Below contains code for comparison with JWT-based token implementation.
// They are commented out because they depend on github.com/golang-jwt/jwt/v5 library.
// JWT-based impl. is about 50~100 times slower than the original HMAC256-based implementation.
/*
func GenerateECDSAKey() (privRaw []byte, pubRaw []byte) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecder, _ := x509.MarshalECPrivateKey(priv)
	ecderpub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecder}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecderpub})
}

var privRaw []byte
var privKey *ecdsa.PrivateKey

func init() {
	privRaw, _ = GenerateECDSAKey()
	privKey = lo.Must(jwt.ParseECPrivateKeyFromPEM(privRaw))
}

func signJWT(user string, expiry int64) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": expiry,
		"sub": user,
	}
	return lo.Must(jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privKey))
}

func verifyJWT(token string) (string, error) {
	tok := lo.Must(jwt.Parse(token, func(token *jwt.Token) (any, error) { return &privKey.PublicKey, nil }))
	return tok.Claims.GetSubject()
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
*/
