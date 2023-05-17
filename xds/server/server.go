package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

func redServer(rw http.ResponseWriter, r *http.Request) {
	fmt.Printf("got / red\n")
	io.WriteString(rw, "red!\n")
}
func blueServer(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusAccepted)
	io.WriteString(rw, "blue!\n")
	fmt.Printf("got / blue\n")
}

func main() {
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	l2, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	go http.Serve(l, http.HandlerFunc(redServer))
	go http.Serve(l2, http.HandlerFunc(blueServer))

	select {}
}
