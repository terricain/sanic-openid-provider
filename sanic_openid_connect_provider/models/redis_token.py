import datetime
import logging
import pickle
from typing import Dict, Any, Union, AsyncGenerator

import aioredis

from sanic_openid_connect_provider.utils import masked
from sanic_openid_connect_provider.models.token import TokenStore


logger = logging.getLogger('oicp')


class RedisTokenStore(TokenStore):
    def __init__(self, *args, redis_host: str = 'localhost',
                 port: int = 6379, db: int = 0, **kwargs):
        super(RedisTokenStore, self).__init__(*args, **kwargs)

        self._redis_url = 'redis://{0}:{1}/{2}'.format(redis_host, port, db)
        self._redis = None

    async def setup(self):
        self._redis = await aioredis.create_redis_pool(address=self._redis_url, minsize=4, maxsize=8)

    async def save_token(self, token: Dict[str, Any]):
        try:
            ttl = int(token['expires_at'] - datetime.datetime.now().timestamp())
            key = 'token_' + token['access_token']
            value = pickle.dumps(token)
            await self._redis.set(key=key, value=value, expire=ttl)
            logger.info('Saved token {0}'.format(masked(token['access_token'])))
        except Exception as err:
            logger.exception('Failed to save token {0}'.format(masked(token['access_token'])), exc_info=err)

    async def delete_token_by_access_token(self, access_token: str):
        try:
            key = 'token_' + access_token
            await self._redis.delete(key)
            logger.info('Deleted token {0}'.format(masked(access_token)))
        except Exception as err:
            logger.exception('Failed to delete token {0}'.format(masked(access_token)), exc_info=err)

    async def delete_token_by_code(self, code: str):
        try:
            all_token_keys = await self._redis.keys('token_*')
            if all_token_keys:
                to_delete = []

                # Iterate through all tokens, unpickle them
                # if they stem from this code, invalidate
                all_tokens = await self._redis.mget(*all_token_keys)
                for token_pickle in all_tokens:
                    token = pickle.loads(token_pickle)
                    if token['code'] == code:
                        to_delete.append('token_' + token['access_token'])

                if to_delete:
                    await self._redis.delete(*to_delete)
                    logger.info('Deleted tokens {0}'.format(' '.join([masked(item) for item in to_delete])))

        except Exception as err:
            logger.exception('Failed to delete tokens by code {0}'.format(masked(code)), exc_info=err)

    async def get_token_by_refresh_token(self, refresh_token: str) -> Union[Dict[str, Any], None]:
        try:
            all_token_keys = await self._redis.keys('token_*')
            if all_token_keys:
                # Iterate through all tokens, unpickle them
                all_tokens = await self._redis.mget(*all_token_keys)
                for token_pickle in all_tokens:
                    token = pickle.loads(token_pickle)
                    if token['refresh_token'] == refresh_token:
                        return token

        except Exception as err:
            logger.exception('Failed to get token by refresh token {0}'.format(masked(refresh_token)), exc_info=err)

    async def get_token_by_access_token(self, access_token: str) -> Union[Dict[str, Any], None]:
        try:
            key = 'token_' + access_token
            token_data = await self._redis.get(key)
            if token_data:
                return pickle.loads(token_data)
        except Exception as err:
            logger.exception('Failed to get token {0}'.format(masked(access_token)), exc_info=err)
        return None

    async def all(self) -> AsyncGenerator[Dict[str, Any], None]:
        try:
            all_token_keys = await self._redis.keys('token_*')
            if all_token_keys:
                # Iterate through all tokens, unpickle them
                all_tokens = await self._redis.mget(*all_token_keys)
                for token_pickle in all_tokens:
                    token = pickle.loads(token_pickle)
                    yield token

        except Exception as err:
            logger.exception('Failed to get all tokens', exc_info=err)
