package googleapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func generateTestSAKeyJSON(t *testing.T, clientEmail string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	keyPEM := string(pem.EncodeToMemory(block))

	return []byte(fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "key-id",
		"private_key": %q,
		"client_email": %q,
		"client_id": "123456",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`, keyPEM, clientEmail))
}

func TestNewServiceAccountTokenSource_PureSAMode(t *testing.T) {
	const saEmail = "sa@test-project.iam.gserviceaccount.com"
	keyJSON := generateTestSAKeyJSON(t, saEmail)

	// Pure SA mode: subject matches the SA's own client_email.
	// cfg.Subject should NOT be set, so no DWD is required.
	ts, err := newServiceAccountTokenSource(context.Background(), keyJSON, saEmail, []string{"https://www.googleapis.com/auth/calendar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ts == nil {
		t.Fatalf("expected non-nil token source")
	}
}

func TestNewServiceAccountTokenSource_Impersonation(t *testing.T) {
	const saEmail = "sa@test-project.iam.gserviceaccount.com"
	const userEmail = "user@example.com"
	keyJSON := generateTestSAKeyJSON(t, saEmail)

	// Impersonation mode: subject differs from the SA's client_email.
	// cfg.Subject should be set to the user email (DWD required).
	ts, err := newServiceAccountTokenSource(context.Background(), keyJSON, userEmail, []string{"https://www.googleapis.com/auth/calendar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ts == nil {
		t.Fatalf("expected non-nil token source")
	}
}

func TestTokenSourceForServiceAccountScopes_GOG_SA_KEY_PATH(t *testing.T) {
	const saEmail = "sa@test-project.iam.gserviceaccount.com"
	const userEmail = "user@example.com"
	keyJSON := generateTestSAKeyJSON(t, saEmail)

	// Write SA key to a temp file.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "sa-key.json")
	if err := os.WriteFile(keyPath, keyJSON, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Set GOG_SA_KEY_PATH so tokenSourceForServiceAccountScopes reads
	// the key from this path instead of deriving it from the email.
	t.Setenv("GOG_SA_KEY_PATH", keyPath)

	ts, path, ok, err := tokenSourceForServiceAccountScopes(
		context.Background(), userEmail,
		[]string{"https://www.googleapis.com/auth/calendar"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ts == nil {
		t.Fatal("expected non-nil token source")
	}
	if path != keyPath {
		t.Fatalf("expected path=%q, got %q", keyPath, path)
	}
}

func TestTokenSourceForServiceAccountScopes_GOG_SA_KEY_PATH_NotFound(t *testing.T) {
	t.Setenv("GOG_SA_KEY_PATH", "/nonexistent/sa-key.json")

	_, _, _, err := tokenSourceForServiceAccountScopes(
		context.Background(), "user@example.com",
		[]string{"https://www.googleapis.com/auth/calendar"},
	)
	if err == nil {
		t.Fatal("expected error for nonexistent key path")
	}
}

func TestNewServiceAccountTokenSource_EmptySubject(t *testing.T) {
	const saEmail = "sa@test-project.iam.gserviceaccount.com"
	keyJSON := generateTestSAKeyJSON(t, saEmail)

	// Empty subject: should not set cfg.Subject.
	ts, err := newServiceAccountTokenSource(context.Background(), keyJSON, "", []string{"https://www.googleapis.com/auth/calendar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ts == nil {
		t.Fatalf("expected non-nil token source")
	}
}
