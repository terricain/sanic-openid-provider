Sanic OpenID Connect Provider
=============================

.. image:: https://img.shields.io/pypi/v/sanic_openid_connect_provider.svg
        :target: https://pypi.python.org/pypi/sanic_openid_connect_provider

.. image:: https://img.shields.io/travis/terrycain/sanic-openid-provider.svg
        :target: https://travis-ci.org/terrycain/sanic-openid-provider

.. image:: https://pyup.io/repos/github/terrycain/sanic-openid-provider/shield.svg
     :target: https://pyup.io/repos/github/terrycain/sanic-openid-provider/
     :alt: Updates

It's a work-in-progress, Alpha stage I would say. If anyone finds this useful / wants to use it, drop an issue I'd be
more than happy to fix it up so its actually helpful to someone other than myself.

Last time I checked it passed around 82 / 93 of the OpenID Connect 
Provider Certification tests that appear when you tick ``webfinger``, ``dynamic info discovery``,
``dynamic client registration`` and select ``code`` response type.

It's pretty usable for the authorization code flow. Still needs a fair amount of re-architecting and cleaning up but I'm
trying to make it so you can plug it into various backends like DynamoDB/Redis for token/client storage.

Docs and examples will be coming soon.

Preconditions
-------------

The package expects ``sanic_jinja2`` and ``sanic_session`` to be in use and configured.

Testing
-------

As said above it passes most of the OpenID tests I've ran against it. Below are the ones I haven't passed yet

Signature + Encryption
~~~~~~~~~~~~~~~~~~~~~~

Haven't figured out why the userinfo enc/sig doesnt work yet.

* ``OP-IDToken-SigEnc``
* ``OP-UserInfo-SigEnc``
* ``OP-request_uri-SigEnc``

Claims
~~~~~~

Haven't got around to this bit yet

* ``OP-claims-acr-essential``
* ``OP-claims-acr-voluntary``
* ``OP-claims-acr=1``

Popup
~~~~~

Doesnt display in a popup box

* ``OP-display-popup``

Misc Request Parameters
~~~~~~~~~~~~~~~~~~~~~~~

Haven't dealt with this yet.

* ``OP-Req-acr_values``

Key Rotation
~~~~~~~~~~~~

Need some methods to rotate keys

* ``OP-Rotation-OP-Enc``
* ``OP-Rotation-OP-Sig``
* ``OP-Rotation-RP-Enc``
* ``OP-Rotation-RP-Sig``


Key creation
------------

RSA Key
~~~~~~~

.. code:: bash

    openssl genrsa -nodes -out rsa.pem 4096


ECDSA Key
~~~~~~~~~

.. code:: bash

    openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
    openssl ec -in ec.pem -pubout -out ec.pub


OpenID Connect Node Example
---------------------------

app.js
~~~~~~

.. code:: javascript

    /*
    *
    * Note: This example is a "full" example that registers a new client with the OIDC server each time. This returns a client ID and secret. 
    *       In reality, you should only register once per service and then save the client information for future use.      
    *       I would advise using this script to register your client and test it - It will console.log the ID and secret which you can then hardcode:
    *       https://github.com/panva/node-openid-client#manually-recommended
    *
    *   In production, I import a modified version of this script with promise support. Make sure it's finished discovery before defining your 
    *   error handlers!
    */

    //******* Config
    const config = {
        /* jshint ignore:start */
        //Server we're going to auth with
        authServer: "https://authserver",
        //Access token provided by admin for initial registration
        initialAccessToken: "dcb89d4c-fec4-11e8-8eb2-f2801f1b9fd1",
        //Listen port
        port: 3000,
        //All the settings required to register our client
        registration: {
            //IDP prefers ES256 encryption
            id_token_signed_response_alg: 'ES256',
            //Array of all potential redirect URI's
            redirect_uris: ["http://127.0.0.1:3000/callback", "http://127.0.0.1/callback"],
            //String space-delimited list of all potentially required scopes
            scope: "openid email profile",
            grant_types: ['authorization_code'],
            application_type: 'web',
            //Name of client - For reference only
            client_name: 'Some client',
            subject_type: 'public',
            response_types: ["code"]
        },
        auth: {
            //uri the IDP redirects to after authentication - Must be in the array above
            redirect_uri: "http://127.0.0.1:3000/callback",
            //Scopes we want for authentication
            scope: "openid email profile",
            id_token_signed_response_alg: 'ES256'
        }
        /* jshint ignore:end */
    }

    //******* End Config


    const { Issuer } = require('openid-client');
    const { Strategy } = require('openid-client');
    const session = require('express-session');
    const express = require('express');
    const app = express();
    const passport = require('passport');

    // Set up Express sessions in memory - Please don't do this in production, use something to store your sessions
    // so we can load balance. 
    app.use(session({
        secret: 'asupersecretpassword',
        resave: true,
        saveUninitialized: true
    }));
    //Make sure to initialise before we start discovery
    app.use(passport.initialize());
    app.use(passport.session());

    //Discover settings from OID server
    Issuer.discover(config.authServer)
        .then(customIssuer => {

            const opts = { initialAccessToken: config.initialAccessToken };
            const metadata = config.registration;

            // You only need to do client registration once (ever) - You should do it during development and then hardcode the client id and secret
            // Below is an example of a hardcoded client, rather than a client that registers each time
            // See more in the docs: https://github.com/panva/node-openid-client#manually-recommended
            
                // const client = new customIssuer.Client({
                //         client_id: '83fc3323d3c045a4',
                //         client_secret: '7f9b5e1721a244c989d011839595b766',
                //         id_token_signed_response_alg: 'ES256'
                //     });
            
             customIssuer.Client.register(metadata, opts)
               .then(client => {
                console.log("!!!!! Save this information for re-use later! !!!!!")
                console.log("Client ID:     " + client.client_id)
                console.log("Client Secret: " + client.client_secret)
                console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                console.log("Metadata:      " + JSON.stringify(client.metadata, null, 2))
            
                const params = config.auth;
                // Setting up our strategy + validation function
                passport.use('oidc', new Strategy({client, params, passReqToCallback: null, sessionKey: null, usePKCE: false}, (tokenset, userinfo, done) => {
                    return done(null, userinfo)
                }));
                
                passport.serializeUser((user, done) => {
                    // This is where you'd get any extra locally-stored data from the database or something for accessing in req.user
                    done(null, user);
                });

                passport.deserializeUser((user, done) => {
                    done(null, user);
                });

                // GET /login will start authentication
                app.get('/login', passport.authenticate('oidc'));

                // GET /callback redirected from IDP with code
                app.get('/callback', passport.authenticate('oidc', {
                  successRedirect: '/',
                  failureRedirect: '/login'
                }));

                // Force every other request to check if user is authed, if not then redirect to /login and start auth
                app.use((req, res, next) => {
                    if (!req.user) {
                        res.redirect('/login');
                    } else {
                        next();
                    }
                })

                // Example authenticated endpoint
                app.get('/',(req, res) => {
                    console.log(`User ${req.user.name} has logged in.`);
                    res.send(req.user);
                })


                app.listen(config.port, () => console.log(`Example app listening on port ${config.port}!`))

            });
        })


package.json
~~~~~~~~~~~~

.. code:: json

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
