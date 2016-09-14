package main

import (
	"./db"
	"./server"
	"log"
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
