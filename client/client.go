package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/labbsr0x/goh/gohclient"
	"github.com/labbsr0x/whisper-client/misc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	"github.com/labbsr0x/goh/gohtypes"

	"github.com/labbsr0x/whisper-client/config"
	"golang.org/x/oauth2"
)

// InitFromConfig initialize a whisper client from flags
func (client *WhisperClient) InitFromConfig(config *config.Config) *WhisperClient {
	loginRedirectURI, err := url.Parse(config.LoginRedirectURI)
	gohtypes.PanicIfError("Unable to parse the redirect url", http.StatusInternalServerError, err)

	client.oah = new(oAuthHelper).init(config.HydraPublicURL, loginRedirectURI, config.ClientID, config.ClientSecret, config.Scopes)
	client.hc = new(hydraClient).initHydraClient(config.HydraAdminURL.String(), config.HydraPublicURL.String(), config.ClientID, config.ClientSecret, config.LoginRedirectURI, config.LogoutRedirectURI, config.Scopes)
	client.isPublic = len(strings.ReplaceAll(config.ClientSecret, " ", "")) == 0

	return client
}

// InitFromParams initializes a whisper client from normal params
func (client *WhisperClient) InitFromParams(whisperURL, clientID, clientSecret, loginRedirectURI, logoutRedirectURI string, scopes []string) *WhisperClient {
	hydraAdminURL, hydraPublicURL := misc.RetrieveHydraURLs(whisperURL)

	whisperURI, err := url.Parse(whisperURL)
	gohtypes.PanicIfError("Invalid whisper url", 500, err)
	hydraAdminURI, err := url.Parse(hydraAdminURL)
	gohtypes.PanicIfError("Invalid hydra admin url", 500, err)
	hydraPublicURI, err := url.Parse(hydraPublicURL)
	gohtypes.PanicIfError("Invalid hydra public url", 500, err)

	return client.InitFromConfig(&config.Config{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		WhisperURL:        whisperURI,
		HydraAdminURL:     hydraAdminURI,
		HydraPublicURL:    hydraPublicURI,
		Scopes:            scopes,
		LoginRedirectURI:  loginRedirectURI,
		LogoutRedirectURI: logoutRedirectURI,
	})
}

// CheckCredentials talks to the admin service to check wheather the client_id should be created and fires a client credentials flow accordingly (if pkce, client credentials flow is not fired)
func (client *WhisperClient) CheckCredentials() (t *oauth2.Token, err error) {
	hc, err := client.hc.getHydraOAuth2Client()

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		hc, err = client.hc.createOAuth2Client()
	}

	if err == nil {
		diffScope := func() bool { return hc.Scopes != strings.Join(client.hc.scopes, " ") }
		diffRedirects := func() bool { return !reflect.DeepEqual(hc.RedirectURIs, client.hc.RedirectURIs) }
		diffLogoutRedirects := func() bool { return !reflect.DeepEqual(hc.PostLogoutRedirectURIs, client.hc.PostLogoutRedirectURIs) }

		if diffScope() || diffRedirects() || diffLogoutRedirects() {
			_, err = client.hc.updateOAuth2Client()
		}

		if err == nil && !client.isPublic {
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

	payload := url.Values{"token": []string{token}, "scopes": client.hc.scopes}
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

// GetOAuth2LoginURL retrieves the hydra login url
func (client *WhisperClient) GetOAuth2LoginParams() (string, string, string, error) {
	return client.oah.getLoginParams()
}

// GetOAuth2LogoutURL retrieves the hydra revokeLoginSessions url
func (client *WhisperClient) GetOAuth2LogoutURL(openidToken, postLogoutRedirectURIs string) (string, error) {
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
