package token

import (
	"errors"
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/golang-jwt/jwt/v5"
)

const userinfoKey = "tfa"

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
