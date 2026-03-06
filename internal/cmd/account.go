package cmd

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/secrets"
)

var openSecretsStoreForAccount = secrets.OpenDefault

func requireAccount(flags *RootFlags) (string, error) {
	client := config.DefaultClientName
	var err error
	if flags != nil {
		client, err = config.NormalizeClientNameOrDefault(flags.Client)
	}
	if err != nil {
		return "", err
	}
	if v := strings.TrimSpace(flags.Account); v != "" {
		if resolved, ok, err := resolveAccountAlias(v); err != nil {
			return "", err
		} else if ok {
			return resolved, nil
		}
		if shouldAutoSelectAccount(v) {
			v = ""
		}
		if v != "" {
			return v, nil
		}
	}
	if v := strings.TrimSpace(os.Getenv("GOG_ACCOUNT")); v != "" {
		if resolved, ok, err := resolveAccountAlias(v); err != nil {
			return "", err
		} else if ok {
			return resolved, nil
		}
		if shouldAutoSelectAccount(v) {
			v = ""
		}
		if v != "" {
			return v, nil
		}
	}

	if store, err := openSecretsStoreForAccount(); err == nil {
		if defaultEmail, err := store.GetDefaultAccount(client); err == nil {
			defaultEmail = strings.TrimSpace(defaultEmail)
			if defaultEmail != "" {
				return defaultEmail, nil
			}
		}
		if toks, err := store.ListTokens(); err == nil {
			filtered := make([]secrets.Token, 0, len(toks))
			for _, tok := range toks {
				if strings.TrimSpace(tok.Email) == "" {
					continue
				}
				if tok.Client == client {
					filtered = append(filtered, tok)
				}
			}
			if len(filtered) == 1 {
				if v := strings.TrimSpace(filtered[0].Email); v != "" {
					return v, nil
				}
			}
			if len(filtered) == 0 && len(toks) == 1 {
				if v := strings.TrimSpace(toks[0].Email); v != "" {
					return v, nil
				}
			}
		}
	}

	// Fall back to GOG_SA_KEY_PATH: read client_email from the SA key file.
	if envPath := strings.TrimSpace(os.Getenv("GOG_SA_KEY_PATH")); envPath != "" {
		if email, err := readSAClientEmail(envPath); err == nil && email != "" {
			return email, nil
		}
	}

	// Fall back to service account key files on disk.
	if emails, err := config.ListServiceAccountEmails(); err == nil && len(emails) == 1 {
		if v := strings.TrimSpace(emails[0]); v != "" {
			return v, nil
		}
	}

	return "", usage("missing --account (or set GOG_ACCOUNT, set default via `gog auth manage`, or store exactly one token/service-account)")
}

func readSAClientEmail(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-provided path
	if err != nil {
		return "", err
	}
	var sa struct {
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(data, &sa); err != nil {
		return "", err
	}
	return strings.TrimSpace(sa.ClientEmail), nil
}

func resolveAccountAlias(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "@") || shouldAutoSelectAccount(value) {
		return "", false, nil
	}
	return config.ResolveAccountAlias(value)
}

func shouldAutoSelectAccount(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto", "default":
		return true
	default:
		return false
	}
}
