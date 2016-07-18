// this acts as a simple in memory db to handle users and refresh tokens.
// replace these functions with actual calls to your db

package db

import (
	"github.com/adam-hanna/jwt-auth/examples/detailed/db/models"
	"github.com/adam-hanna/jwt-auth/examples/detailed/randomstrings"
	
	"golang.org/x/crypto/bcrypt"
	"errors"
	"log"
)

// create a database of users
// the map key is the uuid
var users = map[string]models.User{}

// create a database of refresh tokens
// map key is the jti (json token identifier)
// the val doesn't represent anything but could be used to hold "valid", "revoked", etc.
var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}

// password is hashed before getting here
func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	// check to make sure our uuid is unique
	u := models.User{};
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

	users[uuid] = models.User{ username, passwordHash, role }

	return uuid, err
}

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u 			:= users[uuid]
	blankUser 	:= models.User{}

	if blankUser != u {
		// found the user
		return u, nil
	} else {
		return u, errors.New("User not found that matches given uuid")
	}
}

// returns the user and the userId or an error if not found
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

func DeleteRefreshToken(jti string) error {
	delete(refreshTokens, jti)
	return nil
}

func CheckRefreshToken(jti string) bool {
	log.Println("In custom check token id")
	return refreshTokens[jti] != ""
}

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