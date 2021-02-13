import uuid
import logging
import urllib.parse
import datetime
import os
from functools import wraps
from typing import Optional, List, Callable, Awaitable, Dict, Any

import aiohttp
import jwt
import jwcrypto.jwk
import sanic.request
import sanic.response

from sanic_openid_connect_provider.utils import get_scheme, redirect

logger = logging.getLogger('oicp')


class Client(object):
    def __init__(self,
                 client_id: str,
                 client_secret: str,
                 signature_type: str,
                 callback_path: str = '/callback',
                 autodiscover_base: Optional[str] = None,
                 token_url: Optional[str] = None,
                 authorize_url: Optional[str] = None,
                 userinfo_url: Optional[str] = None,
                 jwk_url: Optional[str] = None,
                 access_userinfo: bool = False,
                 scopes: List = ('openid',),
                 post_logon_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
                 ):
        self.id = client_id
        self.secret = client_secret
        self.id_token_sign_type = signature_type
        self.callback_path = callback_path
        self.autodiscover_url = None
        self.issuer = None
        if autodiscover_base:
            self.autodiscover_url = autodiscover_base.rstrip('/') + '/.well-known/openid-configuration'
        else:
            url_parts = urllib.parse.urlsplit(self.token_url)
            self.issuer = '{0}://{1}'.format(url_parts.scheme, url_parts.netloc)

        self.token_url = token_url
        self.authorize_url = authorize_url
        self.userinfo_url = userinfo_url
        self.jwk_url = jwk_url
        self.access_userinfo = access_userinfo
        self.scopes = list(scopes)
        self.scopes.sort()
        self.post_logon_callback = post_logon_callback

        self.jwk_cache = jwcrypto.jwk.JWKSet()

    async def setup(self):
        await self.autodiscover_settings()

    async def autodiscover_settings(self):
        success = True

        if self.autodiscover_url:
            logger.info('Getting OpenID Configuraiton from {0}'.format(self.autodiscover_url))
            try:
                proxy = os.environ.get('http_proxy', os.environ.get('HTTP_PROXY', None))

                async with aiohttp.ClientSession() as session:
                    async with session.get(self.autodiscover_url, proxy=proxy) as resp:
                        json_data = await resp.json()
                        self.issuer = json_data['issuer']
                        self.token_url = json_data['token_endpoint']
                        self.authorize_url = json_data['authorization_endpoint']
                        self.userinfo_url = json_data['userinfo_endpoint']
                        self.jwk_url = json_data['jwks_uri']
                        logger.info('Loaded OpenID Configuration from well-known endpoint')

            except Exception as err:
                logger.exception('Failed to get OpenID Configuration', exc_info=err)
                success = False

            await self.get_jwk_data()

        return success

    def import_keys(self, keys: jwcrypto.jwk.JWKSet):
        for key in keys:
            if not self.jwk_cache.get_key(key.key_id):
                self.jwk_cache.add(key)

    async def get_jwk_data(self):
        if self.jwk_url:
            try:
                proxy = os.environ.get('http_proxy', os.environ.get('HTTP_PROXY', None))

                async with aiohttp.ClientSession() as session:
                    async with session.get(self.jwk_url, proxy=proxy) as resp:
                        json_data = await resp.text()
                        self.import_keys(jwcrypto.jwk.JWKSet.from_json(json_data))
                        # self.jwk_cache.import_keyset(json_data)
                        logger.info('Loaded OpenID JWKs')

            except Exception as err:
                logger.exception('Failed to get OpenID Configuration', exc_info=err)

    @property
    def string_scopes(self) -> str:
        return ' '.join(self.scopes)

    @staticmethod
    def get_callback_url(request: sanic.request):
        scheme = get_scheme(request)
        callback_url = list(urllib.parse.urlparse(request.app.url_for('handle_callback')))
        callback_url[0] = scheme
        callback_url[1] = request.host
        return urllib.parse.urlunparse(callback_url)

    async def handle_callback(self, request: sanic.request) -> sanic.response.BaseHTTPResponse:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        error_description = request.args.get('error_description')

        if state != request.ctx.session['oicp_state']:
            logger.warning('OICP State differs')
            return sanic.response.text('OpenID Connect State does not match request, something went wrong here')

        if error:
            logger.warning('OICP error {0}'.format(error))
            return sanic.response.text('OpenID Connect Error {0} - {1}'.format(error, error_description))

        # Now we ask for token plz
        payload = {
            'client_id': self.id,
            'client_secret': self.secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.get_callback_url(request),
        }

        try:
            proxy = os.environ.get('http_proxy', os.environ.get('HTTP_PROXY', None))

            async with aiohttp.ClientSession() as session:
                async with session.post(self.token_url, data=payload, proxy=proxy) as resp:
                    json_data = await resp.json()

            if 'error' in json_data:
                logger.error('OpenID Connect error. {0}'.format(json_data))
                return sanic.response.text('Failed to get SSO token')

            access_token = json_data['access_token']
            refresh_token = json_data.get('refresh_token')
            id_token = json_data['id_token']

            jwt_header = jwt.get_unverified_header(id_token)
            key_id = jwt_header['kid']

            if jwt_header['alg'] != self.id_token_sign_type:
                # TODO deal with error
                raise NotImplementedError('invalid sign type')

            key = self.jwk_cache.get_key(key_id)
            if not key:
                await self.get_jwk_data()

                key = self.jwk_cache.get_key(key_id)
                if not key:
                    # TODO deal with error
                    raise NotImplementedError('no key')

            try:
                id_token = jwt.decode(id_token, key.export_to_pem(), algorithms=self.id_token_sign_type, audience=self.id)
            except Exception as err:
                logger.exception('Failed to decode ID token', exc_info=err)
                raise NotImplementedError()

            if id_token['nonce'] != request.ctx.session['oicp_nonce']:
                logger.error('Token nonce invalid, possible replay attack')
                raise NotImplementedError()

            request.ctx.session['user'] = id_token
            request.ctx.session['user']['expires_at'] = id_token['exp']
            request.ctx.session['user']['access_token'] = access_token
            request.ctx.session['user']['refresh_token'] = refresh_token
            logger.info('Got valid json token, user authenticated')

            if self.post_logon_callback:
                await self.post_logon_callback(request.ctx.session)

            next_url = request.ctx.session['oicp_redirect']
            del request.ctx.session['oicp_redirect']
            del request.ctx.session['oicp_state']
            del request.ctx.session['oicp_nonce']
            return redirect(next_url)

        except Exception as err:
            logger.exception('Failed to hit token url', exc_info=err)
            return sanic.response.text('Failed to get SSO token')

    def login_required(self):
        def decorator(f):
            @wraps(f)
            async def decorated_function(request: sanic.request, *args, **kwargs) -> sanic.response.BaseHTTPResponse:
                if 'user' in request.ctx.session:
                    if request.ctx.session['user']['expires_at'] > datetime.datetime.now().timestamp():
                        response = await f(request, *args, **kwargs)
                        return response

                    del request.ctx.session['user']

                current_url = list(urllib.parse.urlparse(request.url))
                current_url[0] = get_scheme(request)
                current_url = urllib.parse.urlunparse(current_url)

                state = str(uuid.uuid4())
                nonce = str(uuid.uuid4())
                request.ctx.session['oicp_state'] = state
                request.ctx.session['oicp_redirect'] = current_url
                request.ctx.session['oicp_nonce'] = nonce

                params = {
                    'scope': self.string_scopes,
                    'response_type': 'code',
                    'client_id': self.id,
                    'redirect_uri': self.get_callback_url(request),
                    'state': state,
                    'nonce': nonce
                }

                if not self.authorize_url:
                    if self.autodiscover_url:
                        success = await self.autodiscover_settings()
                        if not success:
                            return sanic.response.text(
                                'SSO client library failed to autodiscover settings')
                    else:
                        # Settings not passed during setup.
                        return sanic.response.text('SSO client library not setup correctly, authorize_url not provided')

                redirect_url = list(urllib.parse.urlparse(self.authorize_url))
                redirect_url[4] = urllib.parse.urlencode(params)
                redirect_url = urllib.parse.urlunparse(redirect_url)

                return redirect(redirect_url)

            return decorated_function
        return decorator

    def login_required_api(self):
        def decorator(f):
            @wraps(f)
            async def decorated_function(request: sanic.request, *args, **kwargs) -> sanic.response.BaseHTTPResponse:
                if 'user' in request.ctx.session:
                    if request.ctx.session['user']['expires_at'] > datetime.datetime.now().timestamp():
                        response = await f(request, *args, **kwargs)
                        return response

                return sanic.response.json({}, status=403)

            return decorated_function
        return decorator
