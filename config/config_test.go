package config

import (
	"net/url"
	"testing"
)

func TestConfigCheck(t *testing.T) {
	conf := &Config{}

	err := conf.Check()

	if err == nil {
		t.Errorf("Expecting error when all config fields are nil")
	}

	if err.Error() != "client-name and client-id cannot be empty" {
		t.Errorf("Expecting error referring to client-name and client-id")
	}

	conf.ClientName = "a name"
	conf.ClientID = "anid"

	err = conf.Check()
	if err.Error() != "hydra-admin-url, hydra-public-url, public-url, login-redirect-url and logout-redirect-url cannot be nil" {
		t.Errorf("Expecting error referring to the url fields")
	}

	conf.LoginRedirectURL, _ = url.Parse("")
	conf.LogoutRedirectURL, _ = url.Parse("")
	conf.PublicURL, _ = url.Parse("")
	conf.HydraAdminURL, _ = url.Parse("")
	conf.HydraPublicURL, _ = url.Parse("")

	err = conf.Check()
	if err.Error() != "hydra-admin-url and hydra-public-url cannot be empty" {
		t.Error("hydra-admin-url and hydra-public-url cannot be empty")
	}

	conf.HydraAdminURL, _ = url.Parse("http://admin")
	conf.HydraPublicURL, _ = url.Parse("http://public")

	err = conf.Check()
	if err != nil {
		t.Error("Not expecting an error")
	}

	conf.ClientSecret = "12345"

	err = conf.Check()
	if err.Error() != "if a client-secret is provided, it must be at least 6 characters long" {
		t.Error("expecting error when provided secret is not empty but less than 6 chars long")
	}
}
