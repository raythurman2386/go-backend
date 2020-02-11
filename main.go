package main

import (
	"fmt"
	"go-backend/app"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()
	router.Use(app.JwtAuthentication) // Attach auth middleware

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println(port)

	err := http.ListenAndServe(":"+port, router)

	if err != nil {
		fmt.Println(err)
	}
}
