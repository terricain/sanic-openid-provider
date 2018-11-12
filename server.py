import datetime
import uuid
import json
import hashlib
import logging
import base64
import binascii
from typing import Dict, Any, Optional, Tuple
from urllib.parse import unquote

import jwt
import sanic.request
import sanic.response
from sanic_jinja2 import SanicJinja2
from sanic_session import Session, InMemorySessionInterface
from jinja2 import FileSystemLoader

from sanic_oicp import setup

import settings


oicp_logger = logging.getLogger('oicp')
oicp_logger.setLevel(logging.INFO)
oicp_logger.addHandler(logging.StreamHandler())

app = sanic.Sanic()
session = Session(app, interface=InMemorySessionInterface())
jinja = SanicJinja2(app, loader=FileSystemLoader('./templates'), enable_async=True)

setup(app)

TOKEN_STORE = {}
CODE_STORE = {}




def create_client_credentials_response_dic(request: sanic.request.Request, params: Dict[str, Any]) -> Dict[str, Any]:
    # See https://tools.ietf.org/html/rfc6749#section-4.4.3

    token = create_token(
        user=None,
        client=params['client_id'],
        scope=params['client_data']['scopes'],
        specific_claims=params['specific_claims'])

    TOKEN_STORE[token['access_token']] = token

    return {
        'access_token': token['access_token'],
        'expires_in': settings.OIDC_PROVIDER_TOKEN_EXPIRE,
        'token_type': 'bearer',
        'scope': params['client_data']['scopes'],
    }


def create_access_token_response_dic(request: sanic.request.Request, params: Dict[str, Any]) -> Dict[str, Any]:
    # See https://tools.ietf.org/html/rfc6749#section-4.3

    token = create_token(
        user=None,
        client=params['client_id'],
        scope=params['client_data']['scopes'],
        specific_claims=params['specific_claims'])

    id_token_dic = create_id_token(
        token=token,
        user=request['session']['user'],
        aud=params['client_id'],
        nonce=params['code_obj']['nonce'],
        at_hash=token['at_hash'],
        request=request,
        scope=token['scope'],
        client_data=params['client_data']
    )

    token['id_token'] = id_token_dic
    TOKEN_STORE[token['access_token']] = token

    if params['client_data']['jwt_alg'] == 'RS256':
        raise NotImplementedError()  # TODO
    elif params['client_data']['jwt_alg'] == 'HS256':
        id_token = jwt.encode(payload=id_token_dic, key=params['client_data']['secret'], algorithm=params['client_data']['jwt_alg'])
    else:
        raise Exception('Unsupported key algorithm.')

    return {
        'access_token': token['access_token'],
        'refresh_token': token['refresh_token'],
        'expires_in': settings.OIDC_PROVIDER_TOKEN_EXPIRE,
        'token_type': 'bearer',
        'id_token': id_token,
    }


@app.route('/login', methods=['GET', 'POST'])  # '/sso/oidc/authorize'
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
    await app.config['oicp_client'].add_client(
        id_='kbyuFDidLLm280LIwVFiazOqjO3ty8KH',
        name='TestClient',
        secret='60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa',
        type_='confidential',  # TODO ??? confidential / public?
        require_consent=False,
        reuse_consent=False,
        scopes=['openid', 'profile', 'email', 'phone', 'address'],
        callback_urls=[
            'https://openidconnect.net/callback',
            "https://op.certification.openid.net:60407/authz_cb",
            "https://op.certification.openid.net:60407/authz_post",
            'https://testjenkins.ficoccs-prod.net/securityRealm/finishLogin'
        ],
        response_types=['code'],
        jwt_algo='HS256',
        prompts=['consent', 'login', 'none'],
        application_type='web'
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
