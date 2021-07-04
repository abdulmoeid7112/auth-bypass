package main


import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

func authReqHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/users/verify" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}
	userID, err := ExtratcUserID(r.Header.Get("Authorization"))
	if err != nil {
		log.Errorf("failed to extract user_id, err: %+v ", err)
		http.Error(w, "Invalid Bearer Token", http.StatusUnauthorized)
		return
	}

	log.Infof("Request Validated for user_id: %s", userID)
}

func ExtratcUserID(tokenString string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(strings.Fields(tokenString)[1], jwt.MapClaims{})
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to parse token string, err:%+v", err))
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return fmt.Sprintf("%s", claims["id"]), nil
	}

	return "", errors.New("failed to extract user_id from claims")
}


func main() {
	fileServer := http.FileServer(http.Dir("./static"))
	http.Handle("/", fileServer)
	http.HandleFunc("/v1/users/verify", authReqHandler)


	fmt.Printf("Starting server at port 8081\n")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}