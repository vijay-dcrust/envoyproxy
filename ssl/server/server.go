package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
)

func echoServer(rw http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	io.Copy(rw, r.Body)
}

func main() {
	// l, err := net.Listen("tcp", ":8080")
	// if err != nil {
	// 	log.Fatal("listen error:", err)
	// }

	// http.Serve(l, http.HandlerFunc(echoServer))
	server := &http.Server{
		Addr: ":9000",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	http.HandleFunc("/", echoServer)
	//log.Fatal(http.ListenAndServeTLS(":9000", "/app/domain.crt", "/app/domain.key", nil))
	log.Fatal(server.ListenAndServeTLS("/app/domain.crt", "/app/domain.key"))
}
