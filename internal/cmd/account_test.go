package cmd

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/secrets"
)

type fakeSecretsStore struct {
	defaultAccount string
	tokens         []secrets.Token
	errDefault     error
	errListTokens  error
}

func (s *fakeSecretsStore) Keys() ([]string, error) { return nil, errors.New("not implemented") }
func (s *fakeSecretsStore) SetToken(string, string, secrets.Token) error {
	return errors.New("not implemented")
}

func (s *fakeSecretsStore) GetToken(string, string) (secrets.Token, error) {
	return secrets.Token{}, errors.New("not implemented")
}
func (s *fakeSecretsStore) DeleteToken(string, string) error { return errors.New("not implemented") }
func (s *fakeSecretsStore) SetDefaultAccount(string, string) error {
	return errors.New("not implemented")
}

func (s *fakeSecretsStore) GetDefaultAccount(string) (string, error) {
	return s.defaultAccount, s.errDefault
}
func (s *fakeSecretsStore) ListTokens() ([]secrets.Token, error) { return s.tokens, s.errListTokens }

func TestRequireAccount_PrefersFlag(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{Account: "flag@example.com"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "flag@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_UsesEnv(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "env@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ResolvesAliasFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	if err := config.WriteConfig(config.File{
		AccountAliases: map[string]string{"work": "alias@example.com"},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	flags := &RootFlags{Account: "work"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alias@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ResolvesAliasEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	if err := config.WriteConfig(config.File{
		AccountAliases: map[string]string{"work": "alias@example.com"},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("GOG_ACCOUNT", "work")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alias@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_AutoUsesDefault(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{Account: "auto"}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{defaultAccount: "default@example.com"}, nil
	}

	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "default@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_Missing(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}
	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRequireAccount_UsesKeyringDefaultAccount(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{defaultAccount: "default@example.com"}, nil
	}

	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "default@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_UsesSingleStoredToken(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{
			tokens: []secrets.Token{{Email: "one@example.com", Client: config.DefaultClientName}},
		}, nil
	}

	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "one@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_MissingWhenMultipleTokensAndNoDefault(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{
			tokens: []secrets.Token{{Email: "a@example.com", Client: config.DefaultClientName}, {Email: "b@example.com", Client: config.DefaultClientName}},
		}, nil
	}

	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRequireAccount_UsesSAKeyPath(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	t.Setenv("GOG_SA_KEY_PATH", "")

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	// Write SA key file to GOG_SA_KEY_PATH
	saKey := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(saKey, []byte(`{"type":"service_account","client_email":"sa@proj.iam.gserviceaccount.com"}`), 0o600); err != nil {
		t.Fatalf("write sa key: %v", err)
	}
	t.Setenv("GOG_SA_KEY_PATH", saKey)

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{}, nil
	}

	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sa@proj.iam.gserviceaccount.com" {
		t.Fatalf("got %q, want sa@proj.iam.gserviceaccount.com", got)
	}
}

func TestRequireAccount_UsesSingleSAKeyFile(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	t.Setenv("GOG_SA_KEY_PATH", "")

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	// Place a single SA key file in gogcli config dir
	dir, err := config.EnsureDir()
	if err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString([]byte("sa@proj.iam.gserviceaccount.com"))
	if err := os.WriteFile(filepath.Join(dir, "sa-"+enc+".json"), []byte(`{"type":"service_account"}`), 0o600); err != nil {
		t.Fatalf("write sa file: %v", err)
	}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{}, nil
	}

	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "sa@proj.iam.gserviceaccount.com" {
		t.Fatalf("got %q, want sa@proj.iam.gserviceaccount.com", got)
	}
}
