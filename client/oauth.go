package client

import (
	"context"
	"fmt"
	"net/url"

	"github.com/labbsr0x/whisper-client/misc"

	"golang.org/x/oauth2"
)

// Init initializes the oauth helper from a whisper client
func (oah *oAuthHelper) init(oauthURL, redirectURL *url.URL, clientID, clientSecret string, scopes []string) (*oAuthHelper, error) {
	if oauthURL == nil {
		return nil, fmt.Errorf("OAuthURL cannot be nil")
	}

	oah.oauthURL = oauthURL
	oah.clientID = clientID
	oah.clientSecret = clientSecret

	rURL := ""
	if redirectURL != nil {
		rURL = redirectURL.String()
	}
	oah.oauth2Client = oah.getXOAuth2Client(rURL, scopes)
	oah._exchange = oah.oauth2Client.Exchange

	return oah, nil
}

// getLoginURL builds the login url to authenticate with whisper
func (oah *oAuthHelper) getLoginParams() (url, codeVerifier, state string) {
	var nonce, codeChallenge string
	state, nonce = misc.GetStateAndNonce()
	codeVerifier, codeChallenge = misc.GetCodeVerifierAndChallenge()
	url = oah.oauth2Client.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", string(nonce)), oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	return
}

// getLogoutURL builds the logout url to unauthenticate with whisper
func (oah *oAuthHelper) getLogoutURL(openidToken, postLogoutRedirectURI string) string {
	path := oah.oauthURL.String() + "/oauth2/sessions/logout"

	if openidToken != "" && postLogoutRedirectURI != "" {
		path = path + "?id_token_hint=" + openidToken + "&post_logout_redirect_uri=" + postLogoutRedirectURI
	}

	return path
}

// ExchangeCodeForToken performs the code exchange for an oauth token
func (oah *oAuthHelper) exchangeCodeForToken(code, codeVerifier, state string) (tokens Tokens, err error) {
	token, err := oah._exchange(context.WithValue(context.Background(), oauth2.HTTPClient, misc.GetNoSSLClient()), code, oauth2.SetAuthURLParam("state", state), oauth2.SetAuthURLParam("code_verifier", string(codeVerifier)))

	if err != nil {
		return
	}

	tokens = Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.Extra("refresh_token").(string),
		OpenIdToken:  token.Extra("id_token").(string),
		Scope:        token.Extra("scope").(string),
	}

	return
}

// getXOAuth2Client gets an oauth2 client to fire authorization flows
func (oah *oAuthHelper) getXOAuth2Client(redirectURL string, scopes []string) *oauth2.Config {
	authURL, _ := oah.oauthURL.Parse("/oauth2/auth")
	tokenURL, _ := oah.oauthURL.Parse("/oauth2/token")

	return &oauth2.Config{
		ClientID:     oah.clientID,
		ClientSecret: oah.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authURL.String(),
			TokenURL:  tokenURL.String(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}
