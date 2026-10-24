// Package session issues and validates ES256 session tokens.
package session

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DefaultTTL = 5 * time.Minute

const tokenIssuer = "pocketcmd"

type Claims struct {
	DeviceID string `json:"-"`
	jwt.RegisteredClaims
	Cnf CnfClaim `json:"cnf"`
}

type CnfClaim struct {
	X5tS256 string `json:"x5t#S256"`
}

type Manager struct {
	key *ecdsa.PrivateKey
	ttl time.Duration
}

func NewManager(key *ecdsa.PrivateKey) *Manager {
	return &Manager{key: key, ttl: DefaultTTL}
}

func (m *Manager) TTL() time.Duration { return m.ttl }

func (m *Manager) Issue(deviceID, certFingerprint string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   deviceID,
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
		Cnf: CnfClaim{X5tS256: certFingerprint},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(m.key)
}

func (m *Manager) Validate(tokenString, certFingerprint string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &m.key.PublicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(tokenIssuer))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	if claims.Cnf.X5tS256 != certFingerprint {
		return nil, fmt.Errorf("channel binding mismatch: token bound to %s, got %s",
			claims.Cnf.X5tS256, certFingerprint)
	}

	claims.DeviceID = claims.RegisteredClaims.Subject
	return claims, nil
}
