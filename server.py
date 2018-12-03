import datetime
import os
import logging
from urllib.parse import unquote

import sanic.request
import sanic.response
from sanic_jinja2 import SanicJinja2
from sanic_session import Session, InMemorySessionInterface
from jinja2 import FileSystemLoader

from sanic_openid_connect_provider import setup_provider

from sanic_openid_connect_provider.models.clients import DynamoDBClientStore
from sanic_openid_connect_provider.models.token import RedisTokenStore
from sanic_openid_connect_provider.models.code import RedisCodeStore

oicp_logger = logging.getLogger('oicp')
oicp_logger.setLevel(logging.INFO)
oicp_logger.addHandler(logging.StreamHandler())

app = sanic.Sanic()
session = Session(app, interface=InMemorySessionInterface())
jinja = SanicJinja2(app, loader=FileSystemLoader('./templates'), enable_async=True)

res_dir = os.path.join(os.path.dirname(__file__), 'resources')

oicp_provider = setup_provider(
    app=app,
    private_keys=[os.path.join(res_dir, 'ec.pem'), os.path.join(res_dir, 'rsa.pem')],
    client_manager_class=DynamoDBClientStore,
    token_manager_class=RedisTokenStore,
    code_manager_class=RedisCodeStore,
    open_client_registration=False,
    client_registration_key='fefe7676-a451-4255-8d05-c435c9cfa9c8'
)

#
# def create_client_credentials_response_dic(request: sanic.request.Request, params: Dict[str, Any]) -> Dict[str, Any]:
#     # See https://tools.ietf.org/html/rfc6749#section-4.4.3
#
#     token = create_token(
#         user=None,
#         client=params['client_id'],
#         scope=params['client_data']['scopes'],
#         specific_claims=params['specific_claims'])
#
#     TOKEN_STORE[token['access_token']] = token
#
#     return {
#         'access_token': token['access_token'],
#         'expires_in': settings.OIDC_PROVIDER_TOKEN_EXPIRE,
#         'token_type': 'bearer',
#         'scope': params['client_data']['scopes'],
#     }
#
#
# def create_access_token_response_dic(request: sanic.request.Request, params: Dict[str, Any]) -> Dict[str, Any]:
#     # See https://tools.ietf.org/html/rfc6749#section-4.3
#
#     token = create_token(
#         user=None,
#         client=params['client_id'],
#         scope=params['client_data']['scopes'],
#         specific_claims=params['specific_claims'])
#
#     id_token_dic = create_id_token(
#         token=token,
#         user=request['session']['user'],
#         aud=params['client_id'],
#         nonce=params['code_obj']['nonce'],
#         at_hash=token['at_hash'],
#         request=request,
#         scope=token['scope'],
#         client_data=params['client_data']
#     )
#
#     token['id_token'] = id_token_dic
#     TOKEN_STORE[token['access_token']] = token
#
#     if params['client_data']['jwt_alg'] == 'RS256':
#         raise NotImplementedError()  # TODO
#     elif params['client_data']['jwt_alg'] == 'HS256':
#         id_token = jwt.encode(payload=id_token_dic, key=params['client_data']['secret'], algorithm=params['client_data']['jwt_alg'])
#     else:
#         raise Exception('Unsupported key algorithm.')
#
#     return {
#         'access_token': token['access_token'],
#         'refresh_token': token['refresh_token'],
#         'expires_in': settings.OIDC_PROVIDER_TOKEN_EXPIRE,
#         'token_type': 'bearer',
#         'id_token': id_token,
#     }


@app.route('/login', methods=['GET', 'POST'])
async def login(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    if request.method == 'GET':

        return await jinja.render_async('login.html', request)

    else:
        # POST
        request['session']['authenticated'] = True
        request['session']['user'] = {
            'username': 'testuser',
            'consent': False,
            'auth_time': datetime.datetime.now().timestamp(),
            'name': 'John Wick',
            'given_name': 'john',
            'family_name': 'wick',
            'gender': 'male',
            'locale': 'en-us',
            'email': 'johnwick@gmail.com',
            'email_verified': True,
            'address': {
                'formatted': '500 On Fire Hose, USA',
                'street_address': '500 On Fire Hose',
                'locality': 'New York',
                'region': 'No clue',
                'postal_code': 'NY12354',
                'country': 'United States of America'
            },
            'phone_number': '07428555555',
            'phone_number_verified': True

        }

        url = unquote(request.args.get('next'))
        return sanic.response.redirect(url)


@app.listener('before_server_start')
async def startup(app, loop):
    await oicp_provider.setup()

    await oicp_provider.clients.add_client(
        id_='kbyuFDidLLm280LIwVFiazOqjO3ty8KH',
        name='TestClient',
        secret='60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa',
        type_='public',  # public or pairwise
        require_consent=False,
        reuse_consent=False,
        scopes=('openid', 'profile', 'email', 'phone', 'address'),
        callback_urls=(
            'https://openidconnect.net/callback',
            "https://op.certification.openid.net:60407/authz_cb",
            "https://op.certification.openid.net:60407/authz_post",
            'https://testjenkins.ficoccs-prod.net/securityRealm/finishLogin',
            'http://127.0.0.1:3000/cb1',
            'http://127.0.0.1:3000/callback',
            'http://localhost:8006/callback'
        ),
        response_types=('code',),
        jwt_algo='ES256',
        prompts=('consent', 'login', 'none'),
        application_type='web',
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8005)
