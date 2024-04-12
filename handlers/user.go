package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/catalinfl/login-auth/misc"
	"github.com/catalinfl/login-auth/models"
	"github.com/go-chi/chi/v5"
)

func GetUser(w http.ResponseWriter, r *http.Request) {

	getJwt, err := r.Cookie("token")

	fmt.Println(getJwt)

	if err != nil {
		http.Error(w, "No JWT cookie", http.StatusBadRequest)
		return
	}

	claims, err := VerifyToken(getJwt.Value)

	if err != nil {
		http.Error(w, "Invalid JWT", http.StatusBadRequest)
		return
	}

	if claims == "" {
		http.Error(w, "Invalid JWT", http.StatusBadRequest)
		return
	}

	id := chi.URLParam(r, "id")

	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	var user models.User

	err = misc.Database.Where("id = ?", id).First(&user).Error

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userJSON, err := json.Marshal(user)

	if err != nil {
		http.Error(w, "Error converting user to JSON", http.StatusInternalServerError)
	}

	w.Write(userJSON)

}
