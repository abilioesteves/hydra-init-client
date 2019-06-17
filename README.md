# Whisper Client
Defines a script and a library to be used when initializing a client app that communicates with Whisper Admin and Whisper OAuth.

# Life cycle and params

This script/lib takes care of creating the Whisper client in case it does not exist.

Given that, when firing up your client app, you'll need to provide a `client-id`, a `client-secret`, a list of allowed `redirect-uris` and Whisper's endpoints `whisper-admin-url` and `whisper-public-url`. 

The scopes that your application is able to ask for when issuing tokens are set via the `scopes` variable.

You can also define the level of event logging by setting the variable `log-level`.

After making sure the client exists in the Whisper instance, this utility starts a client_credentials flow and emits a new Access Token (in case the client has defined a client-secret).

When a client-secret is empty, the client is assumed to be public and can only perform Authorization Code flow with PKCE. Read the [RFC](https://tools.ietf.org/html/rfc7636)) for more info.

# Use as a lib

The following code should get you started:

```
import (
    whisperClient "github.com/abilioesteves/whisper-client/client"
)

...

whisperClient.InitFromParams("http://localhost:4445", "http://localhost:4444", "client", "password", []string{"client-specific-stuff-01 client-specific-stuff-02 "})

t, err := whisperClient.CheckCredentials()

if err == nil {
    tokenString, err = whisperClient.GetTokenASJSONStr(t)
    ...
}

...
```

# Use as a CLI utility

The following command should get you started:

```
./whisper-client --client-id teste --client-secret teste123 --whisper-admin-url http://localhost:4445/ --whisper-public-url http://localhost:4444/ --redirect-uris http://test.com,http://test1.com --log-level debug --scopes test1,test2  > token.json
```
The command above will store the generated token as a file called `token.json`.

# Use it with docker 

To enable the use of the utility abover with other languages, one can create a Docker image with it setting up the oauth client.

To use it with Docker, you can add the utility in build time and call it with the `ENTRYPOINT` command.

Example:

```
...
from abilioesteves/whisper-client:0.0.1 as whisper-client

from alpine

COPY --from=whisper-client /whisper-client /

RUN touch token.json
ENTRYPOINT ["/whisper-client", " > ", "token.json"]
...

```

Then you can reference the `token.json` file in you code and be able to talk with whisper. Other commands will become available in the near future.

**Extra**: To avoid defining multiple same-purpose environment variables, use the `CLIENT_ENV_PREFIX` environment variable to reuse them in your app and in the `whisper-client` utility.





