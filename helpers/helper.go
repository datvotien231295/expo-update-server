package helpers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type NoUpdateAvailableError struct {
	Message string
}

func (e *NoUpdateAvailableError) Error() string {
	return e.Message
}

func createHash(file []byte, hashingAlgorithm crypto.Hash, encoding string) (string, error) {
	hash := hashingAlgorithm.New()
	_, err := hash.Write(file)
	if err != nil {
		return "", err
	}
	digest := hash.Sum(nil)
	if encoding == "base64" {
		return base64.StdEncoding.EncodeToString(digest), nil
	}
	return fmt.Sprintf("%x", digest), nil
}

func getBase64URLEncoding(base64EncodedString string) string {
	return strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(base64EncodedString)
}

func convertToDictionaryItemsRepresentation(obj map[string]string) map[string][]interface{} {
	dict := make(map[string][]interface{})
	for k, v := range obj {
		dict[k] = []interface{}{v, make(map[string]interface{})}
	}
	return dict
}

func SignRSASHA256(data string, privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func getPrivateKeyAsync() (string, error) {
	privateKeyPath := os.Getenv("PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		return "", nil
	}
	pemBuffer, err := ioutil.ReadFile(filepath.Clean(privateKeyPath))
	if err != nil {
		return "", err
	}
	return string(pemBuffer), nil
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
	sort.Slice(directoriesInUpdatesDirectory, func(i, j int) bool {
		return directoriesInUpdatesDirectory[i] > directoriesInUpdatesDirectory[j]
	})
	return filepath.Join(updatesDirectoryForRuntimeVersion, directoriesInUpdatesDirectory[0]), nil
}

type GetAssetMetadataArg struct {
	UpdateBundlePath string
	FilePath         string
	Ext              *string
	IsLaunchAsset    bool
	RuntimeVersion   string
	Platform         string
}

func getAssetMetadataAsync(arg GetAssetMetadataArg) (map[string]interface{}, error) {
	assetFilePath := filepath.Join(arg.UpdateBundlePath, arg.FilePath)
	asset, err := ioutil.ReadFile(filepath.Clean(assetFilePath))
	if err != nil {
		return nil, err
	}
	assetHash, err := createHash(asset, crypto.SHA256, "base64")
	if err != nil {
		return nil, err
	}
	assetHash = getBase64URLEncoding(assetHash)
	key, err := createHash(asset, crypto.MD5, "hex")
	if err != nil {
		return nil, err
	}
	keyExtensionSuffix := "bundle"
	if !arg.IsLaunchAsset {
		keyExtensionSuffix = *arg.Ext
	}
	contentType := "application/javascript"
	if !arg.IsLaunchAsset {
		contentType = mime.TypeByExtension(*arg.Ext)
	}
	return map[string]interface{}{
		"hash":          assetHash,
		"key":           key,
		"fileExtension": fmt.Sprintf(".%s", keyExtensionSuffix),
		"contentType":   contentType,
		"url":           fmt.Sprintf("%s/api/assets?asset=%s&runtimeVersion=%s&platform=%s", os.Getenv("HOSTNAME"), assetFilePath, arg.RuntimeVersion, arg.Platform),
	}, nil
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

func getMetadataAsync(updateBundlePath string, runtimeVersion string) (map[string]interface{}, error) {
	metadataPath := filepath.Join(updateBundlePath, "metadata.json")
	updateMetadataBuffer, err := ioutil.ReadFile(filepath.Clean(metadataPath))
	if err != nil {
		return nil, fmt.Errorf("no update found with runtime version: %s. Error: %v", runtimeVersion, err)
	}
	var metadataJson map[string]interface{}
	if err := json.Unmarshal(updateMetadataBuffer, &metadataJson); err != nil {
		return nil, err
	}
	metadataStat, err := os.Stat(metadataPath)
	if err != nil {
		return nil, err
	}
	id, err := createHash(updateMetadataBuffer, crypto.SHA256, "hex")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"metadataJson": metadataJson,
		"createdAt":    metadataStat.ModTime().Format(time.RFC3339),
		"id":           id,
	}, nil
}

func getExpoConfigAsync(updateBundlePath string, runtimeVersion string) (map[string]interface{}, error) {
	expoConfigPath := filepath.Join(updateBundlePath, "expoConfig.json")
	expoConfigBuffer, err := ioutil.ReadFile(filepath.Clean(expoConfigPath))
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

func truthy(value interface{}) bool {
	return value != nil && value != ""
}
