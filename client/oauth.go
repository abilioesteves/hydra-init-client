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

// GetLoginURL builds the login url to authenticate with whisper
func (oah *oAuthHelper) getLoginURL() (string, error) {
	state, nonce, err := misc.GetStateAndNonce()
	if err == nil {
		codeVerifier, codeChallenge, err := misc.GetCodeVerifierAndChallenge()
		oah.codeVerifier = codeVerifier
		oah.state = state

		if err == nil {
			return oah.oauth2Client.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", string(nonce)), oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")), nil
		}
	}

	return "", err
}

// ExchangeCodeForToken performs the code exchange for an oauth token
func (oah *oAuthHelper) exchangeCodeForToken(code string) (token *oauth2.Token, err error) {
	return oah.oauth2Client.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, misc.GetNoSSLClient()), code, oauth2.SetAuthURLParam("state", oah.state), oauth2.SetAuthURLParam("code_verifier", string(oah.codeVerifier)))
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
