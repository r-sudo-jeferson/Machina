package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type lockFile struct {
	SecurityTools struct {
		Gitleaks struct {
			Version     string `json:"version"`
			Image       string `json:"image"`
			ImageDigest string `json:"imageDigest"`
		} `json:"gitleaks"`
	} `json:"securityTools"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: imageref <toolchains.lock.json>")
	}

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("read toolchains lock: %v", err)
	}
	var lock lockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		fail("decode toolchains lock: %v", err)
	}

	gitleaks := lock.SecurityTools.Gitleaks
	if strings.TrimSpace(gitleaks.Version) == "" || strings.TrimSpace(gitleaks.Image) == "" {
		fail("Gitleaks version/image is not configured")
	}
	if !strings.HasPrefix(gitleaks.ImageDigest, "sha256:") || len(gitleaks.ImageDigest) != len("sha256:")+64 {
		fail("Gitleaks image digest is not a full sha256 digest")
	}
	for _, r := range strings.TrimPrefix(gitleaks.ImageDigest, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", r) {
			fail("Gitleaks image digest contains non-lowercase-hex data")
		}
	}

	fmt.Printf("%s:v%s@%s\n", gitleaks.Image, gitleaks.Version, gitleaks.ImageDigest)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "secretstest imageref: "+format+"\n", args...)
	os.Exit(1)
}
