package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/labbsr0x/goh/gohclient"
	"github.com/labbsr0x/whisper-client/misc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/gorilla/mux"
	"github.com/labbsr0x/goh/gohtypes"

	"github.com/labbsr0x/whisper-client/config"
	"golang.org/x/oauth2"
)

// InitFromConfig initialize a whisper client from flags
func (client *WhisperClient) InitFromConfig(config *config.Config) *WhisperClient {
	gohtypes.PanicIfError("Invalid config", 500, config.Check())

	var err error
	client.oah, err = new(oAuthHelper).init(config.HydraPublicURL, config.LoginRedirectURL, config.ClientID, config.ClientSecret, config.Scopes)
	gohtypes.PanicIfError("Error initializing the oauthHelper", 500, err)
	client.hc = new(hydraClient).initHydraClient(config.HydraAdminURL.String(), config.HydraPublicURL.String(), config.ClientName, config.ClientID, config.ClientSecret, config.PublicURL.String(), config.LoginRedirectURL.String(), config.LogoutRedirectURL.String(), config.Scopes)
	client.whisperURL = config.WhisperURL

	t, err := client.CheckCredentials()
	if err != nil {
		logrus.Warningf("Unable to perform a client credentials flow. This may result in undesirable behaviour. Reason: %v.", err)
	}

	client.Token = t

	return client
}

// InitFromParams initializes a whisper client from normal params
func (client *WhisperClient) InitFromParams(whisperURL, clientName, clientID, clientSecret, publicURL, loginRedirectURL, logoutRedirectURL string, scopes []string) *WhisperClient {
	hydraAdminURL, hydraPublicURL := misc.RetrieveHydraURLs(whisperURL)

	parsedWhisperURL, err := url.Parse(whisperURL)
	gohtypes.PanicIfError("Invalid whisper url", 500, err)
	parsedHydraAdminURL, err := url.Parse(hydraAdminURL)
	gohtypes.PanicIfError("Invalid hydra admin url", 500, err)
	parsedHydraPublicURL, err := url.Parse(hydraPublicURL)
	gohtypes.PanicIfError("Invalid hydra public url", 500, err)
	parsedLoginRedirectURL, err := url.Parse(loginRedirectURL)
	gohtypes.PanicIfError("Invalid login redirect url", 500, err)
	parsedLogoutRedirectURL, err := url.Parse(logoutRedirectURL)
	gohtypes.PanicIfError("Invalid logout redirect url", 500, err)
	parsedPublicURL, err := url.Parse(publicURL)
	gohtypes.PanicIfError("Invalid public client URL", 500, err)

	return client.InitFromConfig(&config.Config{
		ClientName:        clientName,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		WhisperURL:        parsedWhisperURL,
		HydraAdminURL:     parsedHydraAdminURL,
		HydraPublicURL:    parsedHydraPublicURL,
		Scopes:            scopes,
		LoginRedirectURL:  parsedLoginRedirectURL,
		LogoutRedirectURL: parsedLogoutRedirectURL,
		PublicURL:         parsedPublicURL,
	})
}

// CheckCredentials talks to the admin service to check weather the informed client_id should be created and fires a client credentials flow accordingly
// client credentials flow is not fired if a password is not provided
// client credentials flow is also not fired if app is not first-party client
func (client *WhisperClient) CheckCredentials() (t *oauth2.Token, err error) {
	hc, err := client.hc.getHydraOAuth2Client() // if not first-party client, error

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		hc, err = client.hc.createOAuth2Client()
	}

	if err == nil {
		diffName := func() bool { return hc.ClientName != client.hc.clientName }
		diffURL := func() bool { return hc.ClientURI != client.hc.clientURL }
		diffScope := func() bool { return hc.Scopes != strings.Join(client.hc.scopes, " ") }
		diffRedirects := func() bool { return !reflect.DeepEqual(hc.RedirectURIs, client.hc.RedirectURIs) }
		diffLogoutRedirects := func() bool { return !reflect.DeepEqual(hc.PostLogoutRedirectURIs, client.hc.PostLogoutRedirectURIs) }

		if diffName() || diffURL() || diffScope() || diffRedirects() || diffLogoutRedirects() {
			_, err = client.hc.updateOAuth2Client()
		}

		if err == nil && len(client.oah.clientSecret) >= 6 { // only do client credentials flow if a valid password has been informed
			t, err = client.DoClientCredentialsFlow()
		}
	}

	return t, err
}

// GetTokenAsJSONStr stores the token in the environment variables as a json string
func (client *WhisperClient) GetTokenAsJSONStr(t *oauth2.Token) string {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	_ = enc.Encode(t)
	return buf.String()
}

// GetMuxSecurityMiddleware verifies if the client is authorized to make this request
func (client *WhisperClient) GetMuxSecurityMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string
			var token Token
			var err error

			if tokenString, err = misc.GetAccessTokenFromRequest(r); err == nil {
				if token, err = client.IntrospectToken(tokenString); err == nil {
					if token.Active {
						newR := r.WithContext(context.WithValue(r.Context(), TokenKey, token))
						next.ServeHTTP(w, newR)
						return
					}
				}
			}
			gohtypes.PanicIfError("Unauthorized user", 401, err)
		})
	}
}

// IntrospectToken calls hydra to introspect a access or refresh token
func (client *WhisperClient) IntrospectToken(token string) (result Token, err error) {
	httpClient, err := gohclient.New(nil, client.hc.admin.BaseURL.String())
	if err != nil {
		return Token{}, err
	}

	httpClient.ContentType = "application/x-www-form-urlencoded"
	httpClient.Accept = "application/json"

	payload := url.Values{"token": []string{token}, "scopes": []string{strings.Join(client.hc.scopes, " ")}}
	payloadData := bytes.NewBufferString(payload.Encode()).Bytes()
	logrus.Debugf("IntrospectToken - POST payload: '%v'", payloadData)

	resp, data, err := httpClient.Post("/oauth2/introspect/", payloadData)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}

	return result, err
}

// DoClientCredentialsFlow calls hydra's oauth2/token and starts a client credentials flow
// this method is only correctly executed if the registered client is not public, i.e, has non-empty client secret
func (client *WhisperClient) DoClientCredentialsFlow() (t *oauth2.Token, err error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &Transporter{
			FakeTLSTermination: true,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	})

	u, _ := client.hc.public.BaseURL.Parse("/oauth2/token")
	oauthConfig := clientcredentials.Config{
		ClientID:     client.hc.clientID,
		ClientSecret: client.hc.clientSecret,
		TokenURL:     u.String(),
		Scopes:       client.hc.scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	return oauthConfig.Token(ctx)
}

// GetOAuth2LoginParams retrieves the hydra login url as well as the code_verifier and the state values used to generate such URL
func (client *WhisperClient) GetOAuth2LoginParams() (loginURL, codeVerifier, state string) {
	loginURL, codeVerifier, state = client.oah.getLoginParams()
	return
}

// GetOAuth2LogoutURL retrieves the hydra revokeLoginSessions url
func (client *WhisperClient) GetOAuth2LogoutURL(openidToken, postLogoutRedirectURIs string) string {
	return client.oah.getLogoutURL(openidToken, postLogoutRedirectURIs)
}

// ExchangeCodeForToken retrieves a token provided a valid code
func (client *WhisperClient) ExchangeCodeForToken(code, codeVerifier, state string) (token Tokens, err error) {
	return client.oah.exchangeCodeForToken(code, codeVerifier, state)
}

// RevokeLoginSessions logs out
func (client *WhisperClient) RevokeLoginSessions(subject string) error {
	return client.hc.revokeLoginSessions(subject)
}
