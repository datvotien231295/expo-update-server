package handler

import (
	"encoding/json"
	"errors"
	"expo-updates-server/helpers"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const PRIVATE_KEY_PATH = "code-signing-keys/private-key.pem"

type Metadata struct {
	FileMetadata map[string]PlatformMetadata `json:"fileMetadata"`
}

type PlatformMetadata struct {
	Assets []AssetMetadata `json:"assets"`
	Bundle string          `json:"bundle"`
}

type AssetMetadata struct {
	Path string `json:"path"`
	Ext  string `json:"ext"`
}

type NoUpdateAvailableError struct {
	Message string
}

func (e *NoUpdateAvailableError) Error() string {
	return e.Message
}

func getLatestUpdateBundlePathForRuntimeVersionAsync(runtimeVersion string) (string, error) {
	updatesDirectoryForRuntimeVersion := fmt.Sprintf("updates/%s", runtimeVersion)
	if _, err := os.Stat(updatesDirectoryForRuntimeVersion); os.IsNotExist(err) {
		return "", errors.New("unsupported runtime version")
	}
	filesInUpdatesDirectory, err := ioutil.ReadDir(updatesDirectoryForRuntimeVersion)
	if err != nil {
		return "", err
	}
	var directoriesInUpdatesDirectory []string
	for _, file := range filesInUpdatesDirectory {
		if file.IsDir() {
			directoriesInUpdatesDirectory = append(directoriesInUpdatesDirectory, file.Name())
		}
	}
	if len(directoriesInUpdatesDirectory) == 0 {
		return "", errors.New("no directories found")
	}
	return filepath.Join(updatesDirectoryForRuntimeVersion, directoriesInUpdatesDirectory[0]), nil
}

func getMetadataAsync(updateBundlePath string, runtimeVersion string) (Metadata, error) {
	metadataPath := filepath.Join(updateBundlePath, "metadata.json")
	updateMetadataBuffer, err := ioutil.ReadFile(metadataPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("no update found with runtime version: %s. Error: %v", runtimeVersion, err)
	}
	var metadataJson Metadata
	if err := json.Unmarshal(updateMetadataBuffer, &metadataJson); err != nil {
		return Metadata{}, err
	}
	return metadataJson, nil
}

func getExpoConfigAsync(updateBundlePath string, runtimeVersion string) (map[string]interface{}, error) {
	expoConfigPath := filepath.Join(updateBundlePath, "expoConfig.json")
	expoConfigBuffer, err := ioutil.ReadFile(expoConfigPath)
	if err != nil {
		return nil, fmt.Errorf("no expo config json found with runtime version: %s. Error: %v", runtimeVersion, err)
	}
	var expoConfigJson map[string]interface{}
	if err := json.Unmarshal(expoConfigBuffer, &expoConfigJson); err != nil {
		return nil, err
	}
	return expoConfigJson, nil
}

func convertSHA256HashToUUID(value string) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s", value[:8], value[8:12], value[12:16], value[16:20], value[20:32])
}

func createRollBackDirectiveAsync(updateBundlePath string) (map[string]interface{}, error) {
	rollbackFilePath := filepath.Join(updateBundlePath, "rollback")
	rollbackFileStat, err := os.Stat(rollbackFilePath)
	if err != nil {
		return nil, fmt.Errorf("no rollback found. Error: %v", err)
	}
	return map[string]interface{}{
		"type": "rollBackToEmbedded",
		"parameters": map[string]interface{}{
			"commitTime": rollbackFileStat.ModTime().Format(time.RFC3339),
		},
	}, nil
}

func createNoUpdateAvailableDirectiveAsync() map[string]interface{} {
	return map[string]interface{}{
		"type": "noUpdateAvailable",
	}
}

func getPrivateKeyAsync() (string, error) {
	privateKeyPath := PRIVATE_KEY_PATH
	if privateKeyPath == "" {
		return "", nil
	}
	pemBuffer, err := ioutil.ReadFile(filepath.Clean(privateKeyPath))
	if err != nil {
		return "", err
	}
	return string(pemBuffer), nil
}

//func signRSASHA256(data string, privateKey string) (string, error) {
//	// Implement RSA SHA256 signing logic here
//	return "", nil
//}

func convertToDictionaryItemsRepresentation(obj map[string]string) map[string][]interface{} {
	dict := make(map[string][]interface{})
	for k, v := range obj {
		dict[k] = []interface{}{v, make(map[string]interface{})}
	}
	return dict
}

func putUpdateInResponseAsync(w http.ResponseWriter, r *http.Request, updateBundlePath string, runtimeVersion string, platform string, protocolVersion int) error {
	currentUpdateId := r.Header.Get("expo-current-update-id")
	metadataJson, err := getMetadataAsync(updateBundlePath, runtimeVersion)
	if err != nil {
		return err
	}

	// NoUpdateAvailable directive only supported on protocol version 1
	// for protocol version 0, serve most recent update as normal
	if currentUpdateId == convertSHA256HashToUUID(metadataJson.FileMetadata[platform].Bundle) && protocolVersion == 1 {
		return &NoUpdateAvailableError{Message: "No update available"}
	}

	expoConfig, err := getExpoConfigAsync(updateBundlePath, runtimeVersion)
	if err != nil {
		return err
	}

	platformSpecificMetadata := metadataJson.FileMetadata[platform]
	manifest := map[string]interface{}{
		"id":             convertSHA256HashToUUID(metadataJson.FileMetadata[platform].Bundle),
		"createdAt":      time.Now().Format(time.RFC3339),
		"runtimeVersion": runtimeVersion,
		"assets":         platformSpecificMetadata.Assets,
		"launchAsset":    platformSpecificMetadata.Bundle,
		"metadata":       map[string]interface{}{},
		"extra": map[string]interface{}{
			"expoClient": expoConfig,
		},
	}

	signature := ""
	expectSignatureHeader := r.Header.Get("expo-expect-signature")
	if expectSignatureHeader != "" {
		privateKey, err := getPrivateKeyAsync()
		if err != nil {
			return err
		}
		if privateKey == "" {
			http.Error(w, "Code signing requested but no key supplied when starting server.", http.StatusBadRequest)
			return nil
		}
		manifestString, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		hashSignature, err := helpers.SignRSASHA256(string(manifestString), privateKey)
		if err != nil {
			return err
		}
		dictionary := convertToDictionaryItemsRepresentation(map[string]string{
			"sig":   hashSignature,
			"keyid": "main",
		})
		signature = fmt.Sprintf("%v", dictionary)
	}

	w.Header().Set("expo-protocol-version", fmt.Sprintf("%d", protocolVersion))
	w.Header().Set("expo-sfv-version", "0")
	w.Header().Set("cache-control", "private, max-age=0")
	w.Header().Set("content-type", "application/json")
	if signature != "" {
		w.Header().Set("expo-signature", signature)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(manifest)
	return nil
}

func putRollBackInResponseAsync(w http.ResponseWriter, r *http.Request, updateBundlePath string, protocolVersion int) error {
	if protocolVersion == 0 {
		return errors.New("Rollbacks not supported on protocol version 0")
	}

	embeddedUpdateId := r.Header.Get("expo-embedded-update-id")
	if embeddedUpdateId == "" {
		return errors.New("Invalid Expo-Embedded-Update-ID request header specified.")
	}

	currentUpdateId := r.Header.Get("expo-current-update-id")
	if currentUpdateId == embeddedUpdateId {
		return &NoUpdateAvailableError{Message: "No update available"}
	}

	directive, err := createRollBackDirectiveAsync(updateBundlePath)
	if err != nil {
		return err
	}

	signature := ""
	expectSignatureHeader := r.Header.Get("expo-expect-signature")
	if expectSignatureHeader != "" {
		privateKey, err := getPrivateKeyAsync()
		if err != nil {
			return err
		}
		if privateKey == "" {
			http.Error(w, "Code signing requested but no key supplied when starting server.", http.StatusBadRequest)
			return nil
		}
		directiveString, err := json.Marshal(directive)
		if err != nil {
			return err
		}
		hashSignature, err := helpers.SignRSASHA256(string(directiveString), privateKey)
		if err != nil {
			return err
		}
		dictionary := convertToDictionaryItemsRepresentation(map[string]string{
			"sig":   hashSignature,
			"keyid": "main",
		})
		signature = fmt.Sprintf("%v", dictionary)
	}

	w.Header().Set("expo-protocol-version", "1")
	w.Header().Set("expo-sfv-version", "0")
	w.Header().Set("cache-control", "private, max-age=0")
	w.Header().Set("content-type", "application/json")
	if signature != "" {
		w.Header().Set("expo-signature", signature)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(directive)
	return nil
}

func putNoUpdateAvailableInResponseAsync(w http.ResponseWriter, r *http.Request, protocolVersion int) error {
	if protocolVersion == 0 {
		return errors.New("NoUpdateAvailable directive not available in protocol version 0")
	}

	directive := createNoUpdateAvailableDirectiveAsync()

	signature := ""
	expectSignatureHeader := r.Header.Get("expo-expect-signature")
	if expectSignatureHeader != "" {
		privateKey, err := getPrivateKeyAsync()
		if err != nil {
			return err
		}
		if privateKey == "" {
			http.Error(w, "Code signing requested but no key supplied when starting server.", http.StatusBadRequest)
			return nil
		}
		directiveString, err := json.Marshal(directive)
		if err != nil {
			return err
		}
		hashSignature, err := helpers.SignRSASHA256(string(directiveString), privateKey)
		if err != nil {
			return err
		}
		dictionary := convertToDictionaryItemsRepresentation(map[string]string{
			"sig":   hashSignature,
			"keyid": "main",
		})
		signature = fmt.Sprintf("%v", dictionary)
	}

	w.Header().Set("expo-protocol-version", "1")
	w.Header().Set("expo-sfv-version", "0")
	w.Header().Set("cache-control", "private, max-age=0")
	w.Header().Set("content-type", "application/json")
	if signature != "" {
		w.Header().Set("expo-signature", signature)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(directive)
	return nil
}

func ManifestEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ManifestEndpoint: request = ", r)
	if r.Method != http.MethodGet {
		http.Error(w, "Expected GET.", http.StatusMethodNotAllowed)
		return
	}

	protocolVersionMaybeArray := r.Header["expo-protocol-version"]
	if len(protocolVersionMaybeArray) > 1 {
		http.Error(w, "Unsupported protocol version. Expected either 0 or 1.", http.StatusBadRequest)
		return
	}
	protocolVersion := 0
	if len(protocolVersionMaybeArray) == 1 {
		protocolVersion = 1
	}

	platform := r.Header.Get("expo-platform")
	if platform == "" {
		platform = r.URL.Query().Get("platform")
	}
	if platform != "ios" && platform != "android" {
		http.Error(w, "Unsupported platform. Expected either ios or android.", http.StatusBadRequest)
		return
	}

	runtimeVersion := r.Header.Get("expo-runtime-version")
	if runtimeVersion == "" {
		runtimeVersion = r.URL.Query().Get("runtime-version")
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

	fmt.Println("ManifestEndpoint: updateBundlePath = ", updateBundlePath)

	updateType, err := getTypeOfUpdateAsync(updateBundlePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	switch updateType {
	case "NORMAL_UPDATE":
		err = putUpdateInResponseAsync(w, r, updateBundlePath, runtimeVersion, platform, protocolVersion)
		fmt.Println("ManifestEndpoint: normal update = ", w)
	case "ROLLBACK":
		err = putRollBackInResponseAsync(w, r, updateBundlePath, protocolVersion)
		fmt.Println("ManifestEndpoint: rollback update = ", w)
	}

	if err != nil {
		if _, ok := err.(*NoUpdateAvailableError); ok {
			putNoUpdateAvailableInResponseAsync(w, r, protocolVersion)
			fmt.Println("ManifestEndpoint: no update = ", w)
		} else {
			http.Error(w, err.Error(), http.StatusNotFound)
		}
	}

	fmt.Println("ManifestEndpoint: response = ", w)

	dataByte, _ := json.Marshal(w)
	fmt.Println("ManifestEndpoint: response = ", string(dataByte))
}

func getTypeOfUpdateAsync(updateBundlePath string) (string, error) {
	directoryContents, err := ioutil.ReadDir(updateBundlePath)
	if err != nil {
		return "", err
	}
	for _, content := range directoryContents {
		if content.Name() == "rollback" {
			return "ROLLBACK", nil
		}
	}
	return "NORMAL_UPDATE", nil
}
