import logging
from typing import Dict, Any, Union, Optional, AsyncGenerator

import aioboto3
from botocore.config import Config

from sanic_openid_connect_provider.utils import masked
from sanic_openid_connect_provider.models.code import CodeStore


logger = logging.getLogger('oicp')


class DynamoDBCodeStore(CodeStore):
    def __init__(self, *args, table_name: str = 'oidc-codes', region: str = 'eu-west-1',
                 boto_config: Optional[Config] = None, **kwargs):
        super(DynamoDBCodeStore, self).__init__(*args, **kwargs)

        self._table_name = table_name
        self._region = region
        self._boto_config = boto_config
        self._dynamodb_resource = None
        self._table = None

    async def setup(self):
        self._dynamodb_resource = aioboto3.resource('dynamodb', region_name=self._region, config=self._boto_config)
        self._table = self._dynamodb_resource.Table(self._table_name)

    async def _save_code(self, code: Dict[str, Any]):
        try:
            await self._table.put_item(Item=code)
            logger.info('Saved code {0}'.format(masked(code['code'])))
        except Exception as err:
            logger.exception('Failed to save code {0}'.format(masked(code['code'])), exc_info=err)

    async def get_by_id(self, id_: str) -> Union[Dict[str, Any], None]:
        try:
            resp = await self._table.get_item(Key={'code': id_})
            if 'Item' in resp:
                return resp['Item']
        except Exception as err:
            logger.exception('Failed to get code {0}'.format(masked(id_)), exc_info=err)
        return None

    async def mark_used_by_id(self, id_: str):
        try:
            await self._table.update_item(
                Key={'code': id_},
                UpdateExpression='SET used = :u',
                ExpressionAttributeValues={
                    ':u': True
                }
            )
            logger.info('Marked code {0} as used'.format(masked(id_)))
        except Exception as err:
            logger.exception('Failed to mark code {0} as used'.format(masked(id_)), exc_info=err)

    async def all(self) -> AsyncGenerator[Dict[str, Any], None]:
        resp = await self._table.scan()

        for code in resp.get('Items', []):
            yield code
