// Minimal TLS-handshake check for the Go toolchain inside the guest.
// Stdlib only (no external deps) so `go run` needs no module downloads.
// A completed handshake plus any HTTP response (even 401) is a pass; a
// certificate-verification error is a fail. No API key needed.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	resp, err := http.Post("https://api.anthropic.com/v1/messages", "application/json", strings.NewReader("{}"))
	if err != nil {
		fmt.Println("GO_FETCH_ERROR:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("GO_STATUS:", resp.StatusCode)
	fmt.Println("GO_BODY:", string(body))
}
