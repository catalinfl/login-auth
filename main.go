package main

import (
	"net/http"

	"github.com/catalinfl/login-auth/handlers"
	"github.com/catalinfl/login-auth/misc"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	misc.ConnectDB()

	r.Get("/user/{id}", handlers.GetUser)
	r.Post("/register", handlers.Register)
	r.Post("/login", handlers.Login)

	http.ListenAndServe(":3000", r)

}
