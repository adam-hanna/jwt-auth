package server

import (
	"./handlers"
	"log"
	"net/http"
)

// StartServer : start the server
func StartServer(hostname string, port string) error {
	host := hostname + ":" + port

	log.Printf("Listening on: %s", host)

	err := handlers.InitHandlers()
	if err != nil {
		return err
	}

	return http.ListenAndServe(host, nil)
}
