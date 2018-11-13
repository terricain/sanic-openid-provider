import datetime
import hashlib
import logging
import uuid
import base64
import binascii
from typing import Dict, Tuple, Any, Optional, List, Union, TYPE_CHECKING

from sanic_oicp.utils import masked

if TYPE_CHECKING:
    from sanic import Sanic
    from sanic_oicp.models.clients import Client

logger = logging.getLogger('oicp')


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
                        app: Sanic,
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
