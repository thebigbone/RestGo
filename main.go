package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var jwtSecret = []byte("secretkey")

type Task struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	DueDate     time.Time `json:"dueDate"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// temp users
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid request")
		return
	}

	password, ok := users[credentials.Username]
	if !ok || password != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "invalid user or pass")
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Println("cant generate token. try again:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := struct {
		Token string `json:"token"`
	}{
		Token: tokenString,
	}
	json.NewEncoder(w).Encode(response)
}

func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("auth")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "auth token not found")
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "invalid auth token")
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "invalid auth token")
			return
		}
		ctx := context.WithValue(r.Context(), "username", claims.Username)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func createTaskHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	var task Task
	err := json.NewDecoder(r.Body).Decode(&task)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "invalid request")
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "task created for user: %s", username)
}

func getTasksHandler(w http.ResponseWriter, r *http.Request) {
	tasks := []Task{
		{ID: "1", Title: "task1", Description: "some description", DueDate: time.Now()},
		{ID: "2", Title: "task2", Description: "some description", DueDate: time.Now()},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tasks)
}

func updateTaskHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	taskID := mux.Vars(r)["id"]

	var updatedTask Task
	err := json.NewDecoder(r.Body).Decode(&updatedTask)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "invalid request")
		return
	}

	fmt.Fprintf(w, "task with ID %s updated for user: %s", taskID, username)
}

func deleteTaskHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	taskID := mux.Vars(r)["id"]

	fmt.Fprintf(w, "task with ID %s deleted for user: %s", taskID, username)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/tasks", authenticate(createTaskHandler)).Methods("POST")
	r.HandleFunc("/tasks", authenticate(getTasksHandler)).Methods("GET")
	r.HandleFunc("/tasks/{id}", authenticate(updateTaskHandler)).Methods("PUT")
	r.HandleFunc("/tasks/{id}", authenticate(deleteTaskHandler)).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":8080", r))
	fmt.Println("serving at 8080...")
}
