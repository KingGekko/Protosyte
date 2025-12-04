//go:build !debug
// +build !debug

package main

import (
	_ "embed"
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
)

//go:embed forensic_intel_packet.json.gz
var fipData []byte

func main() {
	portalURL := os.Getenv("LE_PORTAL_URL")
	if portalURL == "" {
		log.Fatal("LE_PORTAL_URL environment variable not set")
	}

	portalKey := os.Getenv("LE_PORTAL_KEY")
	if portalKey == "" {
		log.Fatal("LE_PORTAL_KEY environment variable not set")
	}

	// Create request
	req, err := http.NewRequest("POST", portalURL, bytes.NewReader(fipData))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+portalKey)

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Submission failed with status: %d", resp.StatusCode)
	}

	log.Println("[BRIDGE] Submission successful")

	// Self-destruct sequence
	os.Remove("/dev/shm/submission_token.bin")

	// Attempt to shred the binary
	if err := exec.Command("shred", "-n3", "-z", "-u", os.Args[0]).Run(); err == nil {
		os.Exit(0)
	}

	// Fallback: Overwrite binary with zeroes
	fd, err := os.OpenFile(os.Args[0], os.O_WRONLY, 0)
	if err == nil {
		zeros := bytes.NewReader(make([]byte, len(fipData)))
		io.Copy(fd, zeros)
		fd.Close()
	}

	os.Exit(0)
}

