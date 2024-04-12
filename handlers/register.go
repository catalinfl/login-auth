package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/catalinfl/login-auth/misc"
	"github.com/catalinfl/login-auth/models"
	"golang.org/x/crypto/bcrypt"
)

func Register(w http.ResponseWriter, r *http.Request) {

	var user models.User

	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if len(user.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters long", http.StatusBadRequest)
		return
	}

	if len(user.Username) < 3 {
		http.Error(w, "Username must be at least 3 characters long", http.StatusBadRequest)
		return
	}

	regexUser, err := regexp.Compile("^([a-zA-Z0-9]+)$")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !regexUser.MatchString(user.Username) {
		http.Error(w, "Username must contain only letters and numbers", http.StatusBadRequest)
		return
	}

	specialChar := regexp.MustCompile(`[!@#\$%\^&\*\(\)\-_=\+{}\[\]:;\"'<>,\.\?\/\|\\~]`)
	hasNumber := regexp.MustCompile(`[0-9]`)

	if !specialChar.MatchString(user.Password) {
		http.Error(w, "Password must contain a special character", http.StatusBadRequest)
		return
	}

	if !hasNumber.MatchString(user.Password) {
		http.Error(w, "Password must contain a number at least!", http.StatusBadGateway)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	var userDb models.User

	searchForUser := misc.Database.Where("username = ?", user.Username).First(&userDb)

	if searchForUser.RowsAffected > 0 {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	hashedPassword, err := HashPassword(user.Password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user.Password = hashedPassword

	misc.Database.Create(&user)

	userJSONd, _ := json.Marshal(user)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(userJSONd)

}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}
