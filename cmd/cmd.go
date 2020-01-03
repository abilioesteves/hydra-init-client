package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/labbsr0x/whisper-client/client"

	"github.com/labbsr0x/whisper-client/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "whisper-client",
	Short: "An utility for performing an OAuth2 authorization_code and client_credentials flow with Whisper",
	RunE:  Run,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	config.AddFlags(rootCmd.Flags())

	if err := viper.GetViper().BindPFlags(rootCmd.Flags()); err != nil {
		panic(err)
	}
}

func initConfig() {
	viper.SetEnvPrefix(os.Getenv("WHISPER_CLIENT_ENV_PREFIX")) // all
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv() // read in environment variables that match
}

// Run defines what should happen when the user runs 'whisper-client'
func Run(cmd *cobra.Command, args []string) (err error) {
	config := new(config.Config).InitFromViper(viper.GetViper())
	whisperClient := new(client.WhisperClient).InitFromConfig(config) // init will only succeed after a token gets emitted
	tokenJSONString := whisperClient.GetTokenAsJSONStr(whisperClient.Token)
	fmt.Printf(tokenJSONString)
	return nil
}
