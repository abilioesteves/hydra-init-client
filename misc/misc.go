package misc

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/labbsr0x/goh/gohclient"
	"github.com/labbsr0x/goh/gohtypes"
	"github.com/ory/x/randx"
	"net/http"
	"strings"
)

func RetrieveHydraURLs(baseURL string) (string, string) {
	httpClient, err := gohclient.New(nil, baseURL)
	gohtypes.PanicIfError("Unable to create a client", http.StatusInternalServerError, err)

	httpClient.ContentType = "application/x-www-form-urlencoded"
	httpClient.Accept = "application/json"

	resp, data, err := httpClient.Get("/hydra")
	if err != nil || resp == nil || resp.StatusCode != 200 {
		gohtypes.Panic("Unable to retrieve the hydra urls", http.StatusInternalServerError)
	}

	var result = make(map[string]string)

	err = json.Unmarshal(data, &result)
	gohtypes.PanicIfError("Unable to unmarshal json", http.StatusInternalServerError, err)

	return result["hydraAdminUrl"], result["hydraPublicUrl"]
}

// GetAccessTokenFromRequest is a helper method to recover an Access Token from a http request
func GetAccessTokenFromRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authURLParam := r.URL.Query().Get("token")
	var t string

	if len(authHeader) == 0 && len(authURLParam) == 0 {
		return "", fmt.Errorf("No Authorization Header or URL Param found")
	}

	if len(authHeader) > 0 {
		data := strings.Split(authHeader, " ")

		if len(data) != 2 {
			return "", fmt.Errorf("Bad Authorization Header")
		}

		t = data[0]

		if len(t) == 0 || t != "Bearer" {
			return "", fmt.Errorf("No Bearer Token found")
		}

		t = data[1]

	} else {
		t = authURLParam
	}

	if len(t) == 0 {
		return "", fmt.Errorf("Bad Authorization Token")
	}

	return t, nil
}

func GetStateAndNonce() (state, nonce string) {
	st, _ := randx.RuneSequence(24, randx.AlphaLower) // never gives out error, since max > 0
	ne, _ := randx.RuneSequence(24, randx.AlphaLower) // never gives out error, since max > 0
	state = string(st)
	nonce = string(ne)
	return
}

func GetCodeVerifierAndChallenge() (codeVerifier string, codeChallenge string) {
	cv, _ := randx.RuneSequence(48, randx.AlphaLower) // never gives out error, since max > 0
	codeVerifier = string(cv)

	hash := sha256.New()
	hash.Write([]byte(string(codeVerifier)))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash.Sum([]byte{}))

	return
}

func GetNoSSLClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}
