package main

import (
	"log"
	"github.com/adam-hanna/jwt-auth/examples/detailed/db"
	"github.com/adam-hanna/jwt-auth/examples/detailed/server"
)

var host = "localhost"
var port = "8080"

func main() {
	// init the DB
	db.InitDB()

	// start the server
	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}
}