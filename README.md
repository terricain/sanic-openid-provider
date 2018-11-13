# Sanic OpenID Connect Provider

It's a work-in-progress, Alpha stage I would say. If anyone finds this useful / wants to use it, drop an issue I'd be
more than happy to fix it up so its actually helpful to someone other than myself.

Last time I checked it passed around 75 / 93 of the OpenID Connect 
Provider Certification tests that appear when you tick `webfinger`, `dynamic info discovery`, `dynamic client 
registration` and select `code` response type.

It's pretty usable for the authorization code flow. Still needs a fair amount of re-architecting and cleaning up but I'm
trying to make it so you can plug it into various backends like DynamoDB/Redis for token/client storage.

Docs and examples will be coming soon.

## Testing 

As said above it passes most of the OpenID tests I've ran against it. Below are the ones I haven't passed yet

### Dynamic Client Registration

Haven't yet stored those values on client registration
* `OP-Registration-logo_uri`
* `OP-Registration-policy_uri`
* `OP-Registration-tos_uri`

### Signature + Encryption

Haven't figured out why the userinfo enc/sig doesnt work yet.
* `OP-IDToken-SigEnc`
* `OP-UserInfo-SigEnc`
* `OP-request_uri-SigEnc`

### Popup

Doesnt display in a popup box
* `OP-display-popup`

### Misc Request Parameters

Haven't dealt with this yet.
* `OP-Req-acr_values`
* `OP-Req-max_age=1`
* `OP-Req-max_age=10000`

### Key Rotation

Need some methods to rotate keys
* `OP-Rotation-OP-Enc`
* `OP-Rotation-OP-Sig`
* `OP-Rotation-RP-Enc`
* `OP-Rotation-RP-Sig`



## Key creation

### RSA Key
```bash
openssl genrsa -nodes -out rsa.pem 4096
```

### ECDSA Key

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
openssl ec -in ec.pem -pubout -out ec.pub
```

## OpenID Connect Node Example
### app.js
```javascript
const express = require('express')
const session = require('express-session');
const OICStrategy = require('passport-openid-connect').Strategy;
const app = express()
const passport = require('passport');

const port = 3000

app.use(session({ 
    secret: 'words',
    resave: true,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

const oic = new OICStrategy({
  "issuerHost": "http://9765fb31.ngrok.io",
  "client_id": "kbyuFDidLLm280LIwVFiazOqjO3ty8KH",
  "client_secret": "60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa",
  "redirect_uri": "http://127.0.0.1:3000/callback",
  "scope": "openid email profile"
});

passport.use(oic);
passport.serializeUser(OICStrategy.serializeUser);
passport.deserializeUser(OICStrategy.deserializeUser);

app.get('/login', passport.authenticate('passport-openid-connect', {"successReturnToOrRedirect": "/"}))
app.get('/callback', passport.authenticate('passport-openid-connect', {"callback": true, "successReturnToOrRedirect": "/"}))

app.get('/', (req, res) => {
    console.log(req.user)
    res.json({
        "hello": "world",
        "user": req.user
    })
})

app.listen(port, () => console.log(`Example OpenID Connect app listening on port ${port}!`))
```

### package.json
```json
{
  "name": "openidtest",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "express": "^4.16.4",
    "express-session": "^1.15.6",
    "passport": "^0.4.0",
    "passport-openid-connect": "^0.1.0"
  }
}
```