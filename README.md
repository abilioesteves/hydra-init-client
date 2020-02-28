# Whisper Client

Defines a script and a library to be used when initializing a client app that communicates with Whisper.

## Life cycle and params

This script/lib takes care of creating the Whisper client in case it does not exist.

Given that, when firing up your client app, you'll need to provide a `client-name`, a `client-id`, a `client-secret`, a `public-url`, a `login-redirect-url`, a `logout-redirect-url` and Whisper's endpoint `whisper-url`. 

The scopes that your application is able to ask for when issuing tokens are set via the `scopes` variable.

You can also define the level of event logging by setting the variable `log-level`.

After making sure the client exists in the Whisper instance, this utility starts a `client_credentials` flow and emits a new Access Token (in case the client has defined a `client-secret`).

For better security, Whisper only executes the Authorization Code Flow with PKCE. Read the [RFC 7636](https://tools.ietf.org/html/rfc7636) for more info.

## Use as a lib

The following code should get you started:

```go
import (
    whisperClient "github.com/labbsr0x/whisper-client/client"
)

//...

whisperURL := "http://localhost:7070"
clientName := "Test App"
clientID := "testapp"
clientSecret := "password"
scopes := []string{"offline", "openid", "test1", "test2"}
publicURL := "http://test.app/"
loginRedirectURL := "http://test.app/login"
logoutRedirectURL := "http://test.app/login"

client := whisperClient.InitFromParams(whisperURL, clientName, clientID, clientSecret, publicURL, loginRedirectURI, logoutRedirectURI, scopes)

//...
```

## Use as a CLI utility

Run the dependencies:

```bash
docker-compose up -d
```

Wait a few seconds to stabilize and then:

```bash
./whisper-client --whisper-url http://localhost:7070/ --client-name TesteApp --client-id teste --client-secret password --public-url http://test.app/ --login-redirect-url  http://test.app/login --logout-redirect-url http://test.app/logout --scopes offline,openid,test1,test2 --log-level debug  > token.json
```

The command above will store the generated token as a file called `token.json`.

## Use it with docker

To enable the use of the utility above with other languages, one can create a Docker image with it setting up the oauth client.

To use it with Docker, you can add the utility in build time and call it with the `ENTRYPOINT` command.

Example:

```dockerfile
#...

from labbsr0x/whisper-client:latest as whisper-client

from alpine

COPY --from=whisper-client /whisper-client /

RUN touch token.json
ENTRYPOINT ["/whisper-client", " > ", "token.json"]

#...
```

If `token.json` is not empty or `null`, then everything ran smoothly in your setup. Other commands will become available in the near future.

**Extra**: To avoid defining multiple same-purpose environment variables, use the `CLIENT_ENV_PREFIX` environment variable to reuse them in your app and in the `whisper-client` utility.