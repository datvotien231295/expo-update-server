package handler

import (
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func AssetsEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("AssetsEndpoint: request = ", r)
	query := r.URL.Query()
	assetName := query.Get("asset")
	runtimeVersion := query.Get("runtimeVersion")
	platform := query.Get("platform")

	if assetName == "" {
		http.Error(w, "No asset name provided.", http.StatusBadRequest)
		return
	}

	if platform != "ios" && platform != "android" {
		http.Error(w, "No platform provided. Expected \"ios\" or \"android\".", http.StatusBadRequest)
		return
	}

	if runtimeVersion == "" {
		http.Error(w, "No runtimeVersion provided.", http.StatusBadRequest)
		return
	}

	updateBundlePath, err := getLatestUpdateBundlePathForRuntimeVersionAsync(runtimeVersion)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	metadataJson, err := getMetadataAsync(updateBundlePath, runtimeVersion)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	assetPath := filepath.Clean(assetName)
	var assetMetadata AssetMetadata
	var isLaunchAsset bool
	for _, asset := range metadataJson.FileMetadata[platform].Assets {
		if asset.Path == strings.TrimPrefix(assetName, updateBundlePath+"/") {
			assetMetadata = asset
			break
		}
	}
	isLaunchAsset = metadataJson.FileMetadata[platform].Bundle == strings.TrimPrefix(assetName, updateBundlePath+"/")

	if _, err := os.Stat(assetPath); os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("Asset \"%s\" does not exist.", assetName), http.StatusNotFound)
		return
	}

	asset, err := ioutil.ReadFile(assetPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	contentType := "application/javascript"
	if !isLaunchAsset {
		contentType = mime.TypeByExtension(assetMetadata.Ext)
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(asset)
	fmt.Println("AssetsEndpoint: response = ", w)
}
