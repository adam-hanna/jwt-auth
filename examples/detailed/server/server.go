package server

import (
	"log"
	"net/http"
	"github.com/adam-hanna/jwt-auth/examples/detailed/server/handlers"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port

	log.Printf("Listening on: %s", host)

	err := handlers.InitHandlers()
	if err != nil {
		return err
	}

	return http.ListenAndServe(host, nil)
}