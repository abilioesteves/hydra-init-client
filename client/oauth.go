package client

import (
	"context"
	"github.com/labbsr0x/whisper-client/misc"
	"net/url"

	"golang.org/x/oauth2"
)

// Init initializes the oauth helper from a whisper client
func (oah *oAuthHelper) init(oauthURL, redirectURL *url.URL, clientID, clientSecret string, scopes []string) *oAuthHelper {
	oah.oauthURL = oauthURL
	oah.clientID = clientID
	oah.clientSecret = clientSecret
	oah.oauth2Client = oah.getXOAuth2Client(redirectURL.String(), scopes)

	return oah
}

// getLoginURL builds the login url to authenticate with whisper
func (oah *oAuthHelper) getLoginParams() (url, codeVerifier, state string, err error) {
	var nonce string
	state, nonce, err = misc.GetStateAndNonce()
	if err == nil {
		var codeChallenge string
		codeVerifier, codeChallenge, err = misc.GetCodeVerifierAndChallenge()

		if err == nil {
			return oah.oauth2Client.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", string(nonce)), oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")), codeVerifier, state, err
		}
	}

	return url, codeVerifier, state, err
}

// getLogoutURL builds the logout url to unauthenticate with whisper
func (oah *oAuthHelper) getLogoutURL(openidToken, postLogoutRedirectURI string) (string, error) {
	path := oah.oauthURL.String() + "/oauth2/sessions/logout"

	if openidToken != "" && postLogoutRedirectURI != "" {
		path = path + "?id_token_hint=" + openidToken + "&post_logout_redirect_uri=" + postLogoutRedirectURI
	}

	return path, nil
}

// ExchangeCodeForToken performs the code exchange for an oauth token
func (oah *oAuthHelper) exchangeCodeForToken(code, codeVerifier, state string) (tokens Tokens, err error) {
	token, err := oah.oauth2Client.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, misc.GetNoSSLClient()), code, oauth2.SetAuthURLParam("state", state), oauth2.SetAuthURLParam("code_verifier", string(codeVerifier)))

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
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}
