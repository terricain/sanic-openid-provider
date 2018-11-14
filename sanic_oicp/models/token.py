import datetime
import hashlib
import logging
import uuid
import base64
import binascii
from typing import Dict, Tuple, Any, Optional, List, Union, TYPE_CHECKING

import aioboto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.config import Config

from sanic_oicp.utils import masked

if TYPE_CHECKING:
    from sanic_oicp.models.clients import Client

logger = logging.getLogger('oicp')


class TokenStore(object):
    def __init__(self, provider):
        self._provider = provider

    def set_provider(self, provider):
        self._provider = provider

    async def setup(self):
        pass

    def create_token(self,
                     user: Dict[str, Any],
                     client: 'Client',
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
                        user: Dict[str, Any],
                        client: 'Client',
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
        claims = self._provider.users.get_claims_for_userdata_by_scope(user, scope, specific_claims)
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
    def __init__(self, *args, **kwargs):
        super(InMemoryTokenStore, self).__init__(*args, **kwargs)

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


class DynamoDBTokenStore(TokenStore):
    def __init__(self, *args, table_name: str='oidc-tokens', region: str='eu-west-1', boto_config: Optional[Config]=None, **kwargs):
        super(DynamoDBTokenStore, self).__init__(*args, **kwargs)

        self._store = {}

        self._table_name = table_name
        self._region = region
        self._boto_config = boto_config
        self._dynamodb_resource = None
        self._table = None

    async def setup(self):
        self._dynamodb_resource = aioboto3.resource('dynamodb', region_name=self._region, config=self._boto_config)
        self._table = self._dynamodb_resource.Table(self._table_name)

    async def save_token(self, token: Dict[str, Any]):
        try:
            await self._table.put_item(Item=token)
            logger.info('Saved token {0}'.format(masked(token['access_token'])))
        except Exception as err:
            logger.exception('Failed to save token {0}'.format(masked(token['access_token'])), exc_info=err)

    async def delete_token_by_access_token(self, access_token: str):
        try:
            await self._table.put_item(Key={'access_token': access_token})
            logger.info('Deleted token {0}'.format(masked(access_token)))
        except Exception as err:
            logger.exception('Failed to delete token {0}'.format(masked(access_token)), exc_info=err)

    async def delete_token_by_code(self, code: str):
        resp = await self._table.scan(FilterExpression=Attr('code').eq(code))
        for item in resp.get('Items', []):
            await self.delete_token_by_access_token(item['access_token'])

    async def get_token_by_refresh_token(self, refresh_token: str) -> Union[Dict[str, Any], None]:
        resp = await self._table.scan(FilterExpression=Attr('refresh_token').eq(refresh_token))

        if resp['Count']:
            return resp['Items'][0]
        return None

    async def get_token_by_access_token(self, access_token: str) -> Union[Dict[str, Any], None]:
        try:
            resp = await self._table.get_item(Key={'access_token': access_token})
            if 'Item' in resp:
                return resp['Item']
        except Exception as err:
            logger.exception('Failed to get token {0}'.format(masked(access_token)), exc_info=err)
        return None
