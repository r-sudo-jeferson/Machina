package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type lockFile struct {
	PlatformDependencies struct {
		Keycloak struct {
			Version     string `json:"version"`
			Image       string `json:"image"`
			ImageDigest string `json:"imageDigest"`
		} `json:"keycloak"`
	} `json:"platformDependencies"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: imageref <toolchains.lock.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read lock: %v\n", err)
		os.Exit(1)
	}
	var lock lockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		fmt.Fprintf(os.Stderr, "decode lock: %v\n", err)
		os.Exit(1)
	}
	keycloak := lock.PlatformDependencies.Keycloak
	if keycloak.Version == "" || keycloak.Image == "" || !validDigest(keycloak.ImageDigest) {
		fmt.Fprintln(os.Stderr, "Keycloak image lock is incomplete")
		os.Exit(1)
	}
	fmt.Printf("%s:%s@%s\n", keycloak.Image, keycloak.Version, keycloak.ImageDigest)
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
