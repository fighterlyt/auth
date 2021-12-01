package main

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

var jsonContentType = []string{"application/json; charset=utf-8"}

func main() {

	config := oauth2.Config{
		ClientID:     "usdtpay1",
		ClientSecret: "123",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:8001/authorize",
			TokenURL: "http://localhost:8001/token",
		},
		RedirectURL: "https://8836-91-73-17-193.ngrok.io/code",
		Scopes:      []string{"all"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		loginUrl := config.AuthCodeURL("mainweb")
		w.Write([]byte(loginUrl))
	})

	http.HandleFunc("/code", func(w http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")

		token, err := config.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		marshal, err := json.Marshal(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		header := w.Header()
		if val := header["Content-Type"]; len(val) == 0 {
			header["Content-Type"] = jsonContentType
		}
		w.Write(marshal)

	})
	log.Fatal(http.ListenAndServe(":9096", nil))

}
