package auth

import (
	"crypto/md5"
	"encoding/hex"
)

// HashPassword generates a hash of the password
func HashPassword(password string) string {
	// VULNERABLE: MD5 is cryptographically broken (lines 28-30)
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

// SecureHashPassword uses bcrypt for secure password hashing
func SecureHashPassword(password string) (string, error) {
	// This would use bcrypt in real implementation
	// import "golang.org/x/crypto/bcrypt"
	// return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return "", nil
}
