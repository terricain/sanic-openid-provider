https://github.com/juanifioren/django-oidc-provider

discovery docuemnt url: 
http://localhost:8000/.well-known/openid-configuration
https://e5b00d1c.ngrok.io/.well-known/openid-configuration

webfinger url
http://localhost:8000/.well-known/webfinger
https://e5b00d1c.ngrok.io/.well-known/webfinger



authorization url: http://localhost:8000/sso/oidc/authorize 
https://e5b00d1c.ngrok.io/sso/oidc/authorize



token url: http://localhost:8000/sso/oidc/token 
https://e5b00d1c.ngrok.io/sso/oidc/token



jwk url: http://localhost:8000/sso/oidc/jwk
https://e5b00d1c.ngrok.io/sso/oidc/jwk


userinfo
https://e5b00d1c.ngrok.io/sso/oidc/userinfo


client id: kbyuFDidLLm280LIwVFiazOqjO3ty8KH
client secret: 60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa
scope: openid profile email phone address
callback: https://openidconnect.net/callback


discovery
https://openid.net/specs/openid-connect-discovery-1_0.html

ngrok


Doesn't currently meet:
Dynamic Client Registration
OP-Registration-Sector-Bad
OP-Registration-logo_uri !
OP-Registration-policy_uri !
OP-Registration-tos_uri !

ID Token
OP-IDToken-ES256
OP-IDToken-RS256


Userinfo Endpoint
OP-UserInfo-Enc
OP-UserInfo-RS256
OP-UserInfo-SigEnc

claims Request Parameter
OP-claims-sub

display Request Parameter
OP-display-popup

request Request Parameter
OP-request-Sig
OP-request-Support
OP-request-Unsigned

request_uri Request Parameter
OP-request_uri-Enc
OP-request_uri-SigEnc

Misc Request Parameters
OP-Req-acr_values
OP-Req-max_age=1
OP-Req-max_age=10000

Key Rotation
OP-Rotation-OP-Enc
OP-Rotation-OP-Sig
OP-Rotation-RP-Enc
OP-Rotation-RP-Sig

51 / 74 = 