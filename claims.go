package jwt

import "github.com/dgrijalva/jwt-go"

type TokenClaims struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Type     string `json:"type"`
	IP       string `json:"ip"`
	Secret   string `json:"secret"`
}

type CustomClaims struct {
	TokenClaims TokenClaims
	jwt.StandardClaims
}
