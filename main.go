package main

import (
	"expo-updates-server/handler"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/api/manifest", handler.ManifestEndpoint)
	http.HandleFunc("/api/assets", handler.AssetsEndpoint)
	log.Fatal(http.ListenAndServe(":3000", nil))
}
