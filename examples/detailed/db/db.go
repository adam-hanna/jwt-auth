// this acts as a simple in memory db to handle users and refresh tokens.
// replace these functions with actual calls to your db

package db

import (
	"../randomstrings"
	"./models"

	"errors"
	"golang.org/x/crypto/bcrypt"
	"log"
)

// create a database of users
// the map key is the uuid
var users = map[string]models.User{}

// create a database of refresh tokens
// map key is the jti (json token identifier)
// the val doesn't represent anything but could be used to hold "valid", "revoked", etc.
var refreshTokens map[string]string

// InitDB : Build the "db"
func InitDB() {
	refreshTokens = make(map[string]string)
}

// StoreUser : add user. password is hashed before getting here
func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	// check to make sure our uuid is unique
	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	// generate the bcrypt password hash
	passwordHash, hashErr := generateBcryptHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}

	users[uuid] = models.User{username, passwordHash, role}

	return uuid, err
}

// DeleteUser : remove user
func DeleteUser(uuid string) {
	delete(users, uuid)
}

// FetchUserById : grab a user by their uuid
func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		// found the user
		return u, nil
	}

	return u, errors.New("User not found that matches given uuid")
}

// FetchUserByUsername : returns the user and the userId or an error if not found
func FetchUserByUsername(username string) (models.User, string, error) {
	// so of course this is dumb, but it's just an example
	// your db will be much faster!
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not found that matches given username")
}

// StoreRefreshToken : create and add refresh token to our db
func StoreRefreshToken() (jti string, err error) {
	jti, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return jti, err
	}

	// check to make sure our jti is unique
	for refreshTokens[jti] != "" {
		jti, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return jti, err
		}
	}

	refreshTokens[jti] = "valid"

	return jti, err
}

// DeleteRefreshToken : remove refresh token from db
func DeleteRefreshToken(jti string) error {
	delete(refreshTokens, jti)
	return nil
}

// CheckRefreshToken : is the refresh token valid?
func CheckRefreshToken(jti string) bool {
	log.Println("In custom check token id")
	return refreshTokens[jti] != ""
}

// LogUserIn : log user in with provided credentials
func LogUserIn(username string, password string) (models.User, string, error) {
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)
	if userErr != nil {
		return models.User{}, "", userErr
	}

	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
