package config

import (
	"github.com/labbsr0x/whisper-client/misc"
	"net/url"
	"strings"

	"github.com/labbsr0x/goh/gohtypes"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TokenKey defines the token key type as string
type TokenKey string

const (
	// WhisperTokenEnvKey defines the whisper token key
	WhisperTokenEnvKey TokenKey = "WHISPER_CLIENT_TOKEN"
)

const (
	whisperURL        = "whisper-url"
	clientID          = "client-id"
	clientSecret      = "client-secret"
	logLevel          = "log-level"
	scopes            = "scopes"
	loginRedirectURL  = "login-redirect-url"
	logoutRedirectURL = "logout-redirect-url"
)

// Config define the fields that will be passed via cmd
type Config struct {
	WhisperURL        *url.URL
	HydraAdminURL     *url.URL
	HydraPublicURL    *url.URL
	ClientID          string
	ClientSecret      string
	LogLevel          string
	Scopes            []string
	LoginRedirectURL  *url.URL
	LogoutRedirectURL *url.URL
}

// AddFlags adds flags for Builder.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(whisperURL, "", "Your Whisper base URL")
	flags.String(clientID, "", "The client ID for this app. If hydra doesn't recognize this ID, it will be created as is. If creation fails, execution of this utility panics.")
	flags.String(clientSecret, "", "The client secret for this app, in terms of oauth2 client credentials. Must be at least 6 characters long.")
	flags.String(logLevel, "info", "[optional] The log level (trace, debug, info, warn, error, fatal, panic).")
	flags.String(scopes, "", "[optional] A comma separated list of scopes the client can ask for.")
	flags.String(loginRedirectURL, "", "[optional] Possible redirect_uri this client can talk to when performing an oauth2 login code flow.")
	flags.String(logoutRedirectURL, "", "[optional] Possible redirect_uri this client can talk to when performing an oauth2 logout code flow.")
}

// InitFromViper initializes the flags from Viper.
func (c *Config) InitFromViper(v *viper.Viper) *Config {
	var err error

	c.ClientID = v.GetString(clientID)
	c.ClientSecret = v.GetString(clientSecret)
	c.LogLevel = v.GetString(logLevel)
	c.Scopes = strings.Split(v.GetString(scopes), ",")

	c.LoginRedirectURL, err = url.Parse(v.GetString(loginRedirectURL))
	gohtypes.PanicIfError("Invalid Login Redirect URI", 500, err)

	c.LogoutRedirectURL, err = url.Parse(v.GetString(logoutRedirectURL))
	gohtypes.PanicIfError("Invalid Logout Redirect URI", 500, err)

	c.WhisperURL, err = url.Parse(v.GetString(whisperURL))
	gohtypes.PanicIfError("Invalid whisper url", 500, err)

	hydraAdminURL, hydraPublicURL := misc.RetrieveHydraURLs(c.WhisperURL.String()) // get hydra's configs from the whisper instance

	c.HydraAdminURL, err = url.Parse(hydraAdminURL)
	gohtypes.PanicIfError("Invalid whisper admin url", 500, err)

	c.HydraPublicURL, err = url.Parse(hydraPublicURL)
	gohtypes.PanicIfError("Invalid whisper public url", 500, err)

	c.check()

	logLevel, err := logrus.ParseLevel(c.LogLevel)
	if err != nil {
		logrus.Errorf("Not able to parse log level string. Setting default level: info.")
		logLevel = logrus.InfoLevel
	}

	logrus.SetLevel(logLevel)

	return c
}

func (c *Config) check() {
	if c.ClientID == "" || c.WhisperURL.Host == "" {
		panic("client-id, whisper-url cannot be empty")
	}

	if len(c.ClientSecret) < 6 {
		panic("client-secret must be at least 6 characters long")
	}
}
