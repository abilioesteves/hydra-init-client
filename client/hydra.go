package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/labbsr0x/goh/gohtypes"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/sirupsen/logrus"

	"github.com/labbsr0x/goh/gohclient"
)

// initHydraClient initializes a hydra client
func (client *hydraClient) initHydraClient(hydraAdminURL, hydraPublicURL, clientID, clientSecret string, scopes, redirectURIs []string) *hydraClient {
	var err error
	client.public, err = gohclient.New(nil, hydraPublicURL)
	gohtypes.PanicIfError("Invalid HydraPublicURL", 500, err)
	client.admin, err = gohclient.New(nil, hydraAdminURL)
	gohtypes.PanicIfError("Invalid HydraAdminURL", 500, err)
	client.public.ContentType = "application/json"
	client.admin.ContentType = "application/json"
	client.public.Accept = "application/json"
	client.admin.Accept = "application/json"

	client.scopes = scopes
	client.clientID = clientID
	client.clientSecret = clientSecret
	client.RedirectURIs = redirectURIs

	client.tokenEndpointAuthMethod = "none"
	client.grantTypes = []string{"authorization_code", "refresh_token"}

	if len(strings.ReplaceAll(client.clientSecret, " ", "")) > 0 { // a non public client can perform client_credentials grant type and should inform the secret on all transctions
		client.tokenEndpointAuthMethod = "client_secret_post"
		client.grantTypes = append(client.grantTypes, "client_credentials")
	}
	return client
}

// getHydraOAuth2Client calls hydra to get a clients information
func (client *hydraClient) getHydraOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.admin.BaseURL.Path, "/clients/", client.clientID)

	logrus.Debugf("GetOAuth2Client - GET '%v'", client.clientID)
	resp, data, err := client.admin.Get(p)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// createOAuth2Client calls hydra to create an oauth2 client
func (client *hydraClient) createOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.admin.BaseURL.Path, "/clients")
	payloadData, _ := json.Marshal(
		OAuth2Client{
			ClientID:                client.clientID,
			ClientSecret:            client.clientSecret,
			TokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
			Scopes:                  strings.Join(client.scopes, " "),
			GrantTypes:              client.grantTypes,
			RedirectURIs:            client.RedirectURIs,
		})

	logrus.Debugf("CreateOAuth2Client - POST payload: '%v'", payloadData)
	resp, data, err := client.admin.Post(p, payloadData)
	if err == nil {
		if resp != nil {
			if resp.StatusCode == 201 {
				err = json.Unmarshal(data, &result)
				return result, err
			} else if resp.StatusCode == 409 {
				return nil, fmt.Errorf("Conflict")
			}
			return nil, fmt.Errorf("Internal server error")
		}
		return nil, fmt.Errorf("Expecting response payload to be not null")
	}
	return nil, err
}

// UpdateOAuth2Client updates the scopes and redirect urls of a registered oauth client
func (client *hydraClient) updateOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.admin.BaseURL.Path, "/clients/", client.clientID)
	payloadData, _ := json.Marshal(
		OAuth2Client{
			ClientID:                client.clientID,
			ClientSecret:            client.clientSecret,
			Scopes:                  strings.Join(client.scopes, " "),
			TokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
			RedirectURIs:            client.RedirectURIs,
			GrantTypes:              client.grantTypes,
		})

	logrus.Debugf("UpdateOAuth2Client - PUT payload: '%v'", payloadData)
	resp, data, err := client.admin.Put(p, payloadData)
	if err == nil {
		if resp != nil {
			if resp.StatusCode == 200 {
				err = json.Unmarshal(data, &result)
				return result, err
			}
			return nil, fmt.Errorf("Internal server error")
		}
		return nil, fmt.Errorf("Expecting response payload to be not null")
	}
	return nil, err
}

// IntrospectToken calls hydra to introspect a access or refresh token
func (client *WhisperClient) IntrospectToken(token string) (result Token, err error) {
	httpClient, err := gohclient.New(nil, client.admin.BaseURL.String())
	if err != nil {
		return Token{}, err
	}

	httpClient.ContentType = "application/x-www-form-urlencoded"
	httpClient.Accept = "application/json"

	payload := url.Values{"token": []string{token}, "scopes": client.scopes}
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

	u, _ := client.public.BaseURL.Parse("/oauth2/token")
	oauthConfig := clientcredentials.Config{
		ClientID:     client.clientID,
		ClientSecret: client.clientSecret,
		TokenURL:     u.String(),
		Scopes:       client.scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	return oauthConfig.Token(ctx)
}

// Logout call hydra service and logs the user out
func (client *hydraClient) Logout(subject string) error {
	resp, _, err := client.admin.Delete(fmt.Sprintf("/oauth2/auth/sessions/login?subject=%v", subject))

	if err == nil {
		if resp != nil {
			logrus.Debugf("Logout: %v - %v", subject, resp.StatusCode)
			if resp.StatusCode == 204 || resp.StatusCode == 201 {
				return nil
			} else if resp.StatusCode == 404 {
				return fmt.Errorf("Not found")
			}
			return fmt.Errorf("Internal server error")
		}
		return fmt.Errorf("Expecting response payload to be not null")
	}

	return err
}
