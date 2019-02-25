import logging
from typing import Dict, Any, Optional, Union, AsyncGenerator

import aioboto3
from boto3.dynamodb.conditions import Attr
from botocore.config import Config

from sanic_openid_connect_provider.utils import masked
from sanic_openid_connect_provider.models.token import TokenStore

logger = logging.getLogger('oicp')


class DynamoDBTokenStore(TokenStore):
    def __init__(self, *args, table_name: str = 'oidc-tokens',
                 region: str = 'eu-west-1', boto_config: Optional[Config] = None, **kwargs):
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

    async def all(self) -> AsyncGenerator[Dict[str, Any], None]:
        resp = await self._table.scan()

        for code in resp.get('Items', []):
            yield code
