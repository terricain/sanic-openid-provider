# Okta OpenID Connect example

## Requirements

Needs:

* sanic
* sanic-jinja2
* sanic-session
* sanic-openid-connect-provider

## Okta Requirements

You need the authorisation server, looks like `https://dev-999999.oktapreview.com/oauth2/default/` - trailing slash as we append `.well-known/openid-configuration`

An application created, using the `Authorization Code` flow. You'll need the Client ID and Client secret from this app. You'll also need 
to configure the login redirect URI. In this example it is `http://localhost:8006/callback`

## Running the example

To run the example you need to provide the following environment variables when running `server.py`

* OKTA_CLIENT_ID - App client ID
* OKTA_CLIENT_SECRET - App client secret
* OKTA_BASE - https://dev-999999.oktapreview.com/oauth2/default/

Then goto http://localhost:8006, there will be a link to a protected page, when clicked you'll be send to okta for authentication (seamless if your
already logged in) and then redirected back to a callback page which deals with the Okta response. The page will then load and you'll see a json
representation of the entire session, the part your interested in is `request.ctx.session['user']`

Should see logging similar to this:
```
[2019-02-18 19:19:33 +0000] [20480] [INFO] Goin' Fast @ http://0.0.0.0:8006
Getting OpenID Configuraiton from https://dev-999999.oktapreview.com/oauth2/default/.well-known/openid-configuration
Loaded OpenID Configuration from well-known endpoint
Loaded OpenID JWKs
[2019-02-18 19:19:34 +0000] [20480] [INFO] Starting worker [20480]
[2019-02-18 19:19:34 +0000] - (sanic.access)[INFO][127.0.0.1:35412]: GET http://localhost:8006/secret  302 0
Got valid json token, user authenticated
[2019-02-18 19:19:41 +0000] - (sanic.access)[INFO][127.0.0.1:35412]: GET http://localhost:8006/callback?code=11111111111111111111&state=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee  302 0
[2019-02-18 19:19:41 +0000] - (sanic.access)[INFO][127.0.0.1:35412]: GET http://localhost:8006/secret  200 1415
```