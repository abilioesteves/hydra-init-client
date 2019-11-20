package client

import (
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/labbsr0x/goh/gohclient"
)

type key string

const (
	// TokenKey defines the key that shall be used to store a token in a requests' context
	TokenKey key = "token"
)

// WhisperClient holds the info and structures a whisper client must
type WhisperClient struct {
	hc       *hydraClient
	oah      *oAuthHelper
	isPublic bool
}

// hydraClient holds data and methods to communicate with an hydra service instance
type hydraClient struct {
	public       *gohclient.Default
	admin        *gohclient.Default
	scopes       []string
	clientID     string
	clientSecret string
	RedirectURIs []string
	PostLogoutRedirectURIs []string

	tokenEndpointAuthMethod string
	grantTypes              []string
}

// oAuthHelper holds the info and methods to help integrate with oauth
type oAuthHelper struct {
	codeVerifier string
	oauthURL     *url.URL
	clientID     string
	clientSecret string
	oauth2Client *oauth2.Config
	state        string
}

type Tokens struct {
	AccessToken string
	RefreshToken string
	OpenIdToken string
	Scope string
}

// Token holds a hydra token's data
type Token struct {
	Active            bool                   `json:"active"`
	Audiences         []string               `json:"aud,omitempty"`
	ClientID          string                 `json:"client_id"`
	Expiration        int64                  `json:"exp"`
	Extra             map[string]interface{} `json:"ext,omitempty"`
	IssuedAt          int64                  `json:"iat"`
	IssuerURL         string                 `json:"iss"`
	NotBefore         int64                  `json:"nbf"`
	ObfuscatedSubject string                 `json:"obfuscated_subject,omitempty"`
	Scope             string                 `json:"scope"`
	Subject           string                 `json:"sub"`
	TokenType         string                 `json:"token_type"`
	Username          string                 `json:"username"`
}

// ConsentRequestInfo holds ory hydra's information with regards to a consent request
type ConsentRequestInfo struct {
	ACR                          string                 `json:"acr,omitempty"`
	Challenge                    string                 `json:"challenge,omitempty"`
	Client                       OAuth2Client           `json:"client,omitempty"`
	Context                      map[string]interface{} `json:"context,omitempty"`
	LoginChallenge               string                 `json:"login_challenge,omitempty"`
	LoginSessionID               string                 `json:"login_session_id,omitempty"`
	OIDCContext                  interface{}            `json:"oidc_context,omitempty"`
	RequestURL                   string                 `json:"request_url,omitempty"`
	RequestedAccessTokenAudience []string               `json:"requested_access_token_audience,omitempty"`
	RequestedScope               []string               `json:"requested_scope,omitempty"`
	Skip                         bool                   `json:"skip,omitempty"`
	Subject                      string                 `json:"subject,omitempty"`
}

// LoginRequestInfo holds ory hydra's information with regards to a login request
type LoginRequestInfo struct {
	Challenge                    string               `json:"challenge,omitempty"`
	Client                       OAuth2Client         `json:"client,omitempty"`
	OIDCContext                  OpenIDConnectContext `json:"oidc_context,omitempty"`
	RequestURL                   string               `json:"request_url,omitempty"`
	RequestedAccessTokenAudience []string             `json:"requested_access_token_audience,omitempty"`
	RequestedScope               []string             `json:"requested_scope,omitempty"`
	SessionID                    string               `json:"session_id,omitempty"`
	Skip                         bool                 `json:"skip,omitempty"`
	Subject                      string               `json:"subject,omitempty"`
}

// OAuth2Client holds the data of an oauth2 hydra client
type OAuth2Client struct {
	AllowedCorsOrigins        []string             `json:"allowed_cors_origins,omitempty"`
	Audience                  []string             `json:"audience,omitempty"`
	ClientID                  string               `json:"client_id,omitempty"`
	ClientName                string               `json:"client_name,omitempty"`
	ClientSecret              string               `json:"client_secret,omitempty"`
	ClientSecretExpiresAt     int64                `json:"client_secret_expires_at,omitempty"`
	ClientURI                 string               `json:"client_uri,omitempty"`
	Contacts                  []string             `json:"contacts,omitempty"`
	CreatedAt                 string               `json:"created_at,omitempty"`
	GrantTypes                []string             `json:"grant_types,omitempty"`
	JWKs                      SwaggerJSONWebKeySet `json:"jwks,omitempty"`
	JWKsURI                   string               `json:"jwks_uri,omitempty"`
	LogoURI                   string               `json:"logo_uri,omitempty"`
	Owner                     string               `json:"owner,omitempty"`
	PolicyURI                 string               `json:"policy_uri,omitempty"`
	PostLogoutRedirectURIs    []string             `json:"post_logout_redirect_uris,omitempty"`
	RedirectURIs              []string             `json:"redirect_uris,omitempty"`
	RequestObjectSigningAlg   string               `json:"request_object_signing_alg,omitempty"`
	RequestURIs               []string             `json:"request_uris,omitempty"`
	ResponseTypes             []string             `json:"response_types,omitempty"`
	Scopes                    string               `json:"scope,omitempty"`
	SectorIdentifierURI       string               `json:"sector_identifier_uri,omitempty"`
	SubjectType               string               `json:"subject_type,omitempty"`
	TokenEndpointAuthMethod   string               `json:"token_endpoint_auth_method,omitempty"`
	TosURI                    string               `json:"tos_uri,omitempty"`
	UpdatedAt                 string               `json:"updated_at,omitempty"`
	UserinfoSignedResponseAlg string               `json:"userinfo_signed_response_alg,omitempty"`
}

// OpenIDConnectContext optional information about the OpenID connect request
type OpenIDConnectContext struct {
	ACRValues         []string               `json:"acr_values,omitempty"`
	Display           string                 `json:"display,omitempty"`
	IDTokenHintClaims map[string]interface{} `json:"id_token_hint_claims,omitempty"`
	LoginHint         string                 `json:"login_hint,omitempty"`
	UILocales         []string               `json:"ui_locales,omitempty"`
}

// IntrospectTokenRequestPayload holds the data to communicate with hydra's introspect token api
type IntrospectTokenRequestPayload struct {
	Token string `json:"token"`
	Scope string `json:"scope"`
}

// SwaggerJSONWebKeySet holds the information of a JSON Web Key Set
type SwaggerJSONWebKeySet struct {
	Keys []interface{} `json:"keys"`
}

// SwaggerJSONWebKey holds the informationf of a JSON Web key
type SwaggerJSONWebKey struct {
	ALG string   `json:"alg"`
	CRV string   `json:"crv"`
	D   string   `json:"d"`
	DP  string   `json:"dp"`
	DQ  string   `json:"dq"`
	E   string   `json:"e"`
	K   string   `json:"k"`
	KID string   `json:"kid"`
	KTY string   `json:"kty"`
	N   string   `json:"n"`
	P   string   `json:"p"`
	Q   string   `json:"q"`
	QI  string   `json:"qi"`
	USE string   `json:"use"`
	X   string   `json:"x"`
	X5C []string `json:"x5c"`
	Y   string   `json:"y"`
}

// Transporter to enable the definition of a FakeTLSTermination
type Transporter struct {
	*http.Transport
	FakeTLSTermination bool
}

// RoundTrip overwrites the parent transport round trip to enable/disable fake tls termination
func (t *Transporter) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.FakeTLSTermination {
		req.Header.Set("X-Forwarded-Proto", "https")
	}

	return t.Transport.RoundTrip(req)
}
