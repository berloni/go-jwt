package jwt

import (
	"errors"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func NewToken(key string, claims CustomClaims, duration int64) (string, error) {
	// set expiration date
	claims.ExpiresAt = time.Now().Add(time.Minute * time.Duration(duration)).Unix()

	// encode token
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	jwtEncoded, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}

	return jwtEncoded, nil
}

func DecodeToken(key string, tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if key == "" {
			return nil, errors.New("jwt: key is required")
		}
		return []byte(key), nil
	})
	if err != nil && !strings.Contains(err.Error(), "token is expired") {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)

	if ok && !token.Valid && err != nil && strings.Contains(err.Error(), "token is expired") {
		return claims, err
	}
	if ok && token.Valid && err == nil {
		return claims, nil
	}

	return nil, errors.New("jwt: decoding and validation failed")
}

func ValidateTokenClaims(requestClaims CustomClaims, storedClaims TokenClaims) error {
	if requestClaims.TokenClaims.Secret != storedClaims.Secret {
		return errors.New("jwt: invalid token claims")
	}

	return nil
}

func ValidateToken(key string, tokenString string, storedClaims TokenClaims) error {
	claims, err := DecodeToken(key, tokenString)
	if err != nil {
		return err
	}
	err = ValidateTokenClaims(*claims, storedClaims)
	if err != nil {
		return err
	}

	return nil
}
