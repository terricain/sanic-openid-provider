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
