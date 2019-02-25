import datetime
import logging
import pickle
from typing import Dict, Any, Union, AsyncGenerator

import aioredis

from sanic_openid_connect_provider.utils import masked
from sanic_openid_connect_provider.models.code import CodeStore


logger = logging.getLogger('oicp')


class RedisCodeStore(CodeStore):
    def __init__(self, *args, redis_host: str = 'localhost', port: int = 6379, db: int = 0, **kwargs):
        super(RedisCodeStore, self).__init__(*args, **kwargs)

        self._redis_url = 'redis://{0}:{1}/{2}'.format(redis_host, port, db)
        self._redis = None

    async def setup(self):
        self._redis = await aioredis.create_redis_pool(address=self._redis_url, minsize=4, maxsize=8)

    async def _save_code(self, code: Dict[str, Any]):
        try:
            ttl = int(code['expires_at'] - datetime.datetime.now().timestamp())
            key = 'code_' + code['code']
            value = pickle.dumps(code)
            await self._redis.set(key=key, value=value, expire=ttl)
            logger.info('Saved code {0}'.format(masked(code['code'])))
        except Exception as err:
            logger.exception('Failed to save code {0}'.format(masked(code['code'])), exc_info=err)

    async def get_by_id(self, id_: str) -> Union[Dict[str, Any], None]:
        result = None

        try:
            key = 'code_' + id_
            pickled_value = await self._redis.get(key=key)
            if pickled_value:
                result = pickle.loads(pickled_value)
        except Exception as err:
            logger.exception('Failed to get code {0}'.format(masked(id_)), exc_info=err)
        return result

    async def mark_used_by_id(self, id_: str):
        try:
            code = await self.get_by_id(id_)
            code['used'] = True
            await self._save_code(code)
            logger.info('Marked code {0} as used'.format(masked(id_)))
        except Exception as err:
            logger.exception('Failed to mark code {0} as used'.format(masked(id_)), exc_info=err)

    async def all(self) -> AsyncGenerator[Dict[str, Any], None]:
        try:
            all_code_keys = await self._redis.keys('code_*')
            if all_code_keys:
                # Iterate through all tokens, unpickle them
                all_codes = await self._redis.mget(*all_code_keys)
                for code_pickle in all_codes:
                    code = pickle.loads(code_pickle)
                    yield code

        except Exception as err:
            logger.exception('Failed to get all codes', exc_info=err)
