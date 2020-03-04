package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuthHelper(t *testing.T) {

	// test init with empty oauthURL
	oah, err := new(oAuthHelper).init(nil, nil, "", "", []string{})
	if err == nil {
		t.Errorf("Expecting oAuthHelper.init to return error when oauthURL is nil")
	}

	// test init with empty redirect url
	oauthURL, _ := url.Parse("http://hydra")
	oah, err = new(oAuthHelper).init(oauthURL, nil, "", "", []string{})
	if err != nil {
		t.Errorf("Not expecting error with the provided params")
	}

	// testing loginURL with empty redirect URL
	loginURL, codeVerifier, state := oah.getLoginParams()
	if loginURL == "" || !strings.Contains(loginURL, "nonce") || !strings.Contains(loginURL, "code_challenge") || !strings.Contains(loginURL, "state") || !strings.Contains(loginURL, "code_challenge_method") {
		t.Errorf("Expecting a login URL with a nonce, a state, a code_challenge and a code_challenge_method")
	}

	if codeVerifier == state {
		t.Errorf("Expecting codeVerifier to be different than state")
	}

	// testing logoutURL with empty redirect URL
	logoutURL := oah.getLogoutURL("anopenidtoken.body.signature", "http://arandomurl")

	if logoutURL == "" {
		t.Errorf("Expecting a valid, non-empty, logoutURL")
	}

	if !strings.Contains(logoutURL, "id_token_hint") || !strings.Contains(logoutURL, "post_logout_redirect_uri") {
		t.Errorf("Expecting logoutURL id_token_hint and post_logout_redirect_uri to be part of the logoutURL when non-empty openIDToken and postLogout are informed")
	}

	// testing getXOAuth2Client
	config := oah.getXOAuth2Client("", []string{})

	if config == nil {
		t.Errorf("Expecting oauth2 config to be non-empty")
	}

	if config.ClientID != oah.clientID {
		t.Errorf("Expecting config client id to be the same as oah.ClientID")
	}

	if config.ClientSecret != oah.clientSecret {
		t.Errorf("Expecting config client secret to be the same as oah.ClientSecret")
	}

	if !strings.Contains(config.Endpoint.AuthURL, oah.oauthURL.String()) {
		t.Errorf("Expecting config AuthURL to be based upon oah.oauthURl")
	}

	if !strings.Contains(config.Endpoint.TokenURL, oah.oauthURL.String()) {
		t.Errorf("Expecting config TokenURL to be based upon oah.oauthURl")
	}

	if !strings.Contains(config.Endpoint.AuthURL, "/oauth2/auth") {
		t.Errorf("Expecting config AuthURL to have path '/oauth2/auth'")
	}

	if !strings.Contains(config.Endpoint.TokenURL, "/oauth2/token") {
		t.Errorf("Expecting config TokenURL to have path '/oauth2/token'")
	}

	if config.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Errorf("Expecting oauht2 config auth style to be always in params")
	}

	// testing exchange code for token with err
	oah._exchange = func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
		return nil, fmt.Errorf("Testing exchange with error")
	}

	tokens, err := oah.exchangeCodeForToken("acode", "averifier", "astate")

	if err == nil {
		t.Errorf("Expecting err to be not nil")
	}

	if tokens != (Tokens{}) {
		t.Errorf("Expecting tokens to be an empty structure")
	}

	if err != nil && err.Error() != "Testing exchange with error" {
		t.Errorf("Expecting error to be exactly what the custom exchange function above defines")
	}

	// testing exchange code for token with valid Tokens as return
	oah._exchange = func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
		toReturn := new(oauth2.Token)
		toReturn.AccessToken = "this is a token"

		toReturn = toReturn.WithExtra(map[string]interface{}{
			"refresh_token": "a refresh token",
			"id_token":      "an open id token",
			"scope":         "a space separated list of scopes",
		},
		)
		return toReturn, nil
	}

	tokens, err = oah.exchangeCodeForToken("acode", "averifier", "astate")
	if err != nil {
		t.Errorf("Expecting exchangeCodeForToken to run without errors")
	}

	if tokens == (Tokens{}) {
		t.Errorf("Expecting to retrieve valid Tokens")
	}

	if tokens.AccessToken != "this is a token" {
		t.Errorf("Expecting access token 'this is a token'")
	}

	if tokens.OpenIdToken != "an open id token" {
		t.Errorf("Invalid open id token")
	}

	if tokens.RefreshToken != "a refresh token" {
		t.Errorf("Invalid refresh token")
	}

	if tokens.Scope != "a space separated list of scopes" {
		t.Errorf("Invalid space separated list of scopes")
	}
}
