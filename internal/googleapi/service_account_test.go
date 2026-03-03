package googleapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
