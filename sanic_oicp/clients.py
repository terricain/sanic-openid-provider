import uuid
import jwt
import aiohttp
import logging
from typing import Tuple, Union, Dict, Optional, Any, AsyncGenerator
import jwcrypto.jwk


logger = logging.getLogger('oicp')


class Client(object):
    def __init__(self, id_: str, name: str, secret: str, type_: str, require_consent: bool,
                 reuse_consent: bool, scopes: Tuple[str, ...], callback_urls: Tuple[str, ...],
                 response_types: Tuple[str, ...], jwt_algo: str, prompts: Tuple[str, ...],
                 application_type: str=None, jwks_url: Tuple[str, ...]=None, post_logout_redirect_urls: Tuple[str, ...]=None,
                 request_urls: Tuple[str, ...]=None, grant_types: Tuple[str, ...] = None, contacts: Tuple[str, ...]=None,
                 expires_at: Optional[int]=None,
                 sector_identifier_uri=None):
        self.id = id_
        self.name = name
        self.secret = secret
        self.type = type_
        self.require_consent = require_consent
        self.reuse_consent = reuse_consent
        self.scopes = frozenset(scopes)
        self.callback_urls = frozenset(callback_urls)
        self.response_types = frozenset(response_types)
        self.jwt_algo = jwt_algo
        self.prompts = frozenset(prompts) if prompts else frozenset()
        self.application_type = application_type

        self.jwks_url = jwks_url
        self.post_logout_redirect_urls = post_logout_redirect_urls
        self.request_urls = request_urls
        self.grant_types = grant_types
        self.contacts = contacts
        self.expires_at = expires_at
        self.sector_identifier_uri = sector_identifier_uri

        self.access_token = uuid.uuid4().hex

        self.jwk = jwcrypto.jwk.JWKSet()

    async def sign(self, payload, jwk_algo=None):
        jwk_algo = jwk_algo if jwk_algo else self.jwt_algo

        if jwk_algo == 'ES256':
            raise NotImplementedError()  # -- TODO use IDP key
        if jwk_algo == 'RS256':
            raise NotImplementedError()  # -- TODO use IDP key
        elif jwk_algo == 'HS256' or jwk_algo is None:
            payload = jwt.encode(payload=payload, key=self.secret, algorithm='HS256')
        elif jwk_algo == 'none':
            payload = jwt.encode(payload=payload, key=None, algorithm='none')
        else:
            raise Exception('Unsupported key algorithm.')

        return payload

    async def load_jwks(self, jwk_dict: Dict[str, Any]=None):

        if self.jwks_url:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.jwks_url) as resp:
                        jwk_data = await resp.json()

                for jwk in jwk_data['keys']:
                    self.jwk.add(jwcrypto.jwk.JWK(**jwk))
            except Exception as err:
                logger.exception('Failed to grab JWKs')

        if jwk_dict:
            for jwk in jwk_dict['keys']:
                self.jwk.add(jwcrypto.jwk.JWK(**jwk))


class ClientStore(object):
    async def get_client_by_id(self, client_id: str) -> Union[Client, None]:
        raise NotImplementedError()

    async def get_client_by_access_token(self, access_token: str) -> Union[Client, None]:
        raise NotImplementedError()

    async def validate_client(self, id_: str, name: str, secret: str, type_, callback_urls: Tuple[str, ...]) -> Tuple[bool, str]:
        logger.info('Validated client {0} - {1}'.format(id_, name))
        return True, ''

    async def add_client(self, id_: str,
                         name: str,
                         secret: str,
                         type_: str,
                         require_consent: bool,
                         reuse_consent: bool,
                         scopes: Tuple[str, ...],
                         callback_urls: Tuple[str, ...],
                         response_types: Tuple[str, ...],
                         jwt_algo: str,
                         prompts: Tuple[str, ...],
                         application_type: str=None) -> Tuple[bool, Union[str, Client]]:
        raise NotImplementedError()

    async def delete_client_by_id(self, client_id: str) -> bool:
        raise NotImplementedError()

    async def all(self) -> AsyncGenerator[Client, None]:
        raise NotImplementedError()


class InMemoryClientStore(ClientStore):
    def __init__(self):
        self._clients: Dict[str, Client] = {}

    async def add_client(self,
                         id_: str,
                         name: str,
                         type_: str,
                         secret: str,
                         callback_urls: Tuple[str, ...],
                         require_consent: bool=False,
                         reuse_consent: bool=False,
                         scopes: Tuple[str, ...]=('profile', 'email', 'phone'),
                         response_types: Tuple[str, ...]=('code',),
                         jwt_algo: str=None,
                         prompts: Tuple[str, ...]=None,
                         application_type: str=None,

                         grant_types: Tuple[str, ...] = None,
                         contacts: Tuple[str, ...] = None,
                         expires_at: Optional[int]= None,
                         jwks_url: Tuple[str, ...]=None,
                         post_logout_redirect_urls: Tuple[str, ...]=None,
                         request_urls: Tuple[str, ...] = None,
                         sector_identifier_uri: str=None


                         ) -> Tuple[bool, Union[str, Client]]:
        valid, err = await self.validate_client(id_, name, secret, type_, callback_urls)
        if not valid:
            return False, err

        client = Client(id_, name, secret, type_, require_consent, reuse_consent,
                        scopes, callback_urls, response_types, jwt_algo, prompts,
                        contacts, jwks_url, post_logout_redirect_urls, request_urls,
                        sector_identifier_uri)
        self._clients[client.id] = client

        logger.info('Added client {0} - {1}'.format(id_, name))
        return True, client

    async def delete_client_by_id(self, client_id: str) -> bool:
        try:
            del self._clients[client_id]
            logger.info('Deleted client {0}'.format(client_id))
        except KeyError:
            pass
        return True

    async def get_client_by_id(self, client_id: str) -> Union[Client, None]:
        try:
            return self._clients[client_id]
        except KeyError:
            return None

    async def get_client_by_access_token(self, access_token: str) -> Union[Client, None]:
        for client in self._clients.values():
            if client.access_token == access_token:
                return client
        return None

    async def get_client_by_key_id(self, key_id: str) -> Union[Client, None]:
        for client in self._clients.values():
            if client.jwk.get_key(key_id):
                return client
        return None

    async def all(self) -> AsyncGenerator[Client, None]:
        for client in self._clients.values():
            yield client
