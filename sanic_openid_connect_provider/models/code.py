import datetime
import logging
import uuid
from typing import Dict, Tuple, Any, Union, TYPE_CHECKING, AsyncGenerator

from sanic_openid_connect_provider.utils import masked

if TYPE_CHECKING:
    from sanic_openid_connect_provider.models.clients import Client


logger = logging.getLogger('oicp')


class CodeStore(object):
    def __init__(self, provider=None):
        self._provider = provider

    def set_provider(self, provider):
        self._provider = provider

    async def setup(self):
        pass

    async def create_code(self,
                          client: 'Client',
                          user: Dict[str, Any],
                          scopes: Tuple[str, ...],
                          code_expire: int,
                          nonce: str = None,
                          code_challenge: str = None,
                          code_challenge_method: str = None,
                          specific_claims: Dict[str, Any] = None):
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
            'specific_claims': specific_claims,
            'auth_time': user['auth_time']
        }

        await self._save_code(code)

        return code

    async def _save_code(self, code: Dict[str, Any]):
        raise NotImplementedError()

    async def get_by_id(self, id_: str) -> Union[Dict[str, Any], None]:
        raise NotImplementedError()

    async def mark_used_by_id(self, id_: str):
        raise NotImplementedError()

    async def all(self) -> AsyncGenerator[Dict[str, Any], None]:
        if False:  # For typing
            yield {}


class InMemoryCodeStore(CodeStore):
    def __init__(self, *args, **kwargs):
        super(InMemoryCodeStore, self).__init__(*args, **kwargs)

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

    async def all(self) -> AsyncGenerator[Dict[str, Any], None]:
        for value in self._store.values():
            yield value
