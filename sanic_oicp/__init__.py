import uuid
import base64
import hashlib
import binascii
import datetime
import logging

from typing import Union, Tuple, Dict, Any, Type, Optional, List

import sanic.request

from sanic_oicp.handlers import well_known_config_handler, well_known_finger_handler, jwk_handler, userinfo_handler, client_register_handler
from sanic_oicp.authorize_endpoint import authorize_handler
from sanic_oicp.token_endpoint import token_handler
from sanic_oicp.utils import masked
from sanic_oicp.users import UserManager
from sanic_oicp.clients import Client, InMemoryClientStore


logger = logging.getLogger('oicp')


def setup(app: sanic.Sanic,
          wellknown_config_path: str='/.well-known/openid-configuration',
          wellknown_finger_path: str='/.well-known/webfinger',
          jwk_path: str='/sso/oidc/jwk',  # TODO oidc -> oicp
          userinfo_path: str='/sso/oidc/userinfo',
          token_path: str='/sso/oidc/token',
          authorize_path: str='/sso/oidc/authorize',
          client_register_path: str='/sso/oidc/client_register',
          login_funcname='login',
          token_expire: int=86400,
          code_expire: int=86400,
          grant_type_password: bool=False,
          user_manager_class: Type[UserManager]=UserManager):

    app.add_route(well_known_config_handler, wellknown_config_path, frozenset({'GET'}))
    app.add_route(well_known_finger_handler, wellknown_finger_path, frozenset({'GET'}))
    app.add_route(jwk_handler, jwk_path, frozenset({'GET'}))
    app.add_route(userinfo_handler, userinfo_path, frozenset({'GET', 'POST'}))
    app.add_route(token_handler, token_path, frozenset({'POST'}))
    app.add_route(authorize_handler, authorize_path, frozenset({'GET', 'POST'}))
    app.add_route(client_register_handler, client_register_path, frozenset({'GET', 'POST'}))

    app.config['oicp_user'] = user_manager_class()
    app.config['oicp_code'] = InMemoryCodeStore()
    app.config['oicp_client'] = InMemoryClientStore()
    app.config['oicp_token'] = InMemoryTokenStore()
    app.config['oicp_login_funcname'] = login_funcname
    app.config['oicp_token_expire'] = token_expire
    app.config['oicp_code_expire'] = code_expire
    app.config['oicp_grant_type_password'] = grant_type_password


class CodeStore(object):
    async def create_code(self,
                       client: Client,
                       user: Dict[str, Any],
                       scopes: Tuple[str, ...],
                       code_expire: int,
                       nonce: str=None,
                       code_challenge: str=None,
                       code_challenge_method: str=None,
                       specific_claims: Dict[str, Any]=None):
        if specific_claims is None:
            specific_claims = {}

        code = {
            'used': False,
            'user': user['username'],
            'client': client.id,
            'code': uuid.uuid4().hex,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
            'expires_at': int(datetime.datetime.now().timestamp() + code_expire),
            'scope': scopes,
            'nonce': nonce,
            # 'is_authentication': is_authentication,
            'specific_claims': specific_claims
        }

        await self._save_code(code)

        return code

    async def _save_code(self, code: Dict[str, Any]):
        raise NotImplementedError()

    async def get_by_id(self, id_: str) -> Union[Dict[str, Any], None]:
        raise NotImplementedError()

    async def mark_used_by_id(self, id_: str):
        raise NotImplementedError()


class InMemoryCodeStore(CodeStore):
    def __init__(self):
        super(InMemoryCodeStore, self).__init__()

        self._store: Dict[str, Any] = {}

    async def _save_code(self, code: Dict[str, Any]):
        self._store[code['code']] = code
        logger.info('Saved code {0}'.format(masked(code['code'])))

    async def get_by_id(self, id_: str) -> Union[Dict[str, Any], None]:
        try:
            code = self._store[id_]

            now = int(datetime.datetime.now().timestamp())
            if now > code['expires_at']:
                del self._store[id_]
                logger.info('Code expired, removing')
                return None

            return code
        except KeyError:
            pass

        return None

    async def mark_used_by_id(self, id_: str):
        try:
            code = self._store[id_]

            code['used'] = True
            logger.info('Marked code {0} as used'.format(masked(code['code'])))
        except KeyError:
            pass


class TokenStore(object):
    def create_token(self,
                     user: Dict[str, Any],
                     client: Client,
                     scope: Tuple[str, ...],
                     expire_delta: int,
                     specific_claims: Dict[str, Any]=None,
                     id_token: Dict[str, Any]=None,
                     code: str=None) -> Dict[str, Any]:
        access_token = uuid.uuid4().hex

        hashed_access_token = hashlib.sha256(access_token.encode('ascii')).hexdigest().encode('ascii')
        hashed_access_token = base64.urlsafe_b64encode(binascii.unhexlify(hashed_access_token[:len(hashed_access_token) // 2])).rstrip(b'=').decode('ascii')

        return {
            'user': user['username'],
            'client': client.id,
            'access_token': access_token,
            'id_token': id_token,
            'refresh_token': uuid.uuid4().hex,
            'expires_at': int(datetime.datetime.now().timestamp() + expire_delta),
            'scope': scope,
            'at_hash': hashed_access_token,
            'code': code,
            'specific_claims': specific_claims
        }

    def create_id_token(self,
                        app: sanic.Sanic,
                        user: Dict[str, Any],
                        client: Client,
                        expire_delta: int,
                        issuer: str,
                        nonce: Optional[str]='',
                        at_hash='',
                        scope: List[str]=None,
                        specific_claims: Dict[str, Any]=None):
        if scope is None:
            scope = []
        if specific_claims is None:
            specific_claims = {}

        # Convert datetimes into timestamps.
        now = int(datetime.datetime.now().timestamp())
        iat_time = now
        exp_time = int(now + expire_delta)
        # auth_time = int(user['auth_time'])

        sub = user['username']
        if client.type == 'pairwise':
            sub = hashlib.sha256(sub.encode()).hexdigest()

        dic = {
            'iss': issuer,
            'sub': sub,
            'aud': client.id,
            'exp': exp_time,
            'iat': iat_time,
            # 'auth_time': auth_time,
        }

        if nonce:
            dic['nonce'] = str(nonce)

        if at_hash:
            dic['at_hash'] = at_hash

        specific_claims = specific_claims.get('id_token', {}).keys()
        claims = app.config['oicp_user'].get_claims_for_userdata_by_scope(user, scope, specific_claims)
        dic.update(claims)

        return dic

    async def save_token(self, token: Dict[str, Any]):
        raise NotImplementedError()

    async def delete_token_by_access_token(self, access_key: str):
        raise NotImplementedError()

    async def delete_token_by_code(self, code: str):
        raise NotImplementedError()

    async def get_token_by_refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        raise NotImplementedError()

    async def get_token_by_access_token(self, access_token: str) -> Union[Dict[str, Any], None]:
        raise NotImplementedError()


class InMemoryTokenStore(TokenStore):
    def __init__(self):
        self._store = {}
        self._client_token_store = {}

    async def save_token(self, token: Dict[str, Any]):
        self._store[token['access_token']] = token
        logger.info('Saved token {0}'.format(masked(token['access_token'])))

    async def delete_token_by_access_token(self, access_token: str):
        try:
            del self._store[access_token]
            logger.info('Deleted token {0}'.format(masked(access_token)))
        except KeyError:
            pass

    async def delete_token_by_code(self, code: str):
        to_delete = []

        for access_token, token in self._store.items():
            if token.get('code') == code:
                to_delete.append(access_token)

        for access_token in to_delete:
            del self._store[access_token]
            logger.info('Deleted token {0}'.format(masked(access_token)))

    async def get_token_by_refresh_token(self, refresh_token: str) -> Union[Dict[str, Any], None]:
        for value in self._store.values():
            if value.get('refresh_token') == refresh_token:
                return value
        return None

    async def get_token_by_access_token(self, access_token: str) -> Union[Dict[str, Any], None]:
        try:
            return self._store[access_token]
        except KeyError:
            return None
