import inspect
import logging
import uuid
from typing import Tuple, Union, Dict, Optional, Any, AsyncGenerator

import aioboto3
import aiohttp
import jwcrypto.common
import jwcrypto.jwe
import jwcrypto.jwk
import jwcrypto.jws
import jwt
import sanic.request
import sanic.response
from boto3.dynamodb.conditions import Attr
from botocore.config import Config

from sanic_openid_connect_provider.utils import masked

logger = logging.getLogger('oicp')


class Client(object):
    def __init__(self,
                 id_: str,
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
                 application_type: str=None,
                 jwks_url: str=None,
                 post_logout_redirect_urls: Tuple[str, ...]=None,
                 request_urls: Tuple[str, ...]=None,
                 grant_types: Tuple[str, ...] = None,
                 contacts: Tuple[str, ...]=None,
                 expires_at: Optional[int]=None,
                 sector_identifier_uri: str=None,
                 userinfo_signed_response_alg: str=None,
                 userinfo_encrypted_response_alg: str=None,
                 userinfo_encrypted_response_enc: str=None,
                 logo_uri: str=None,
                 policy_uri: str=None,
                 tos_uri: str=None,

                 access_token=None,
                 jwk=None,
                 **kwargs):
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
        self.userinfo_signed_response_alg = userinfo_signed_response_alg
        self.userinfo_encrypted_response_alg = userinfo_encrypted_response_alg
        self.userinfo_encrypted_response_enc = userinfo_encrypted_response_enc

        self.access_token = access_token if access_token else uuid.uuid4().hex
        self.jwk = jwcrypto.jwk.JWKSet()
        if jwk:
            self.jwk.import_keyset(jwk)

    async def sign(self, payload, jwk_algo=None, jwk_set: jwcrypto.jwk.JWKSet=None):
        jwk_algo = jwk_algo if jwk_algo else self.jwt_algo

        if jwk_algo == 'ES256':
            if not jwk_set:
                raise RuntimeError('No EC Keys')

            for key in jwk_set:
                if key.key_type == 'EC':
                    try:
                        payload = jwt.encode(
                            payload=payload,
                            key=key.export_to_pem(private_key=True, password=None),
                            algorithm='ES256',
                            headers={'kid': key.key_id}
                        )
                        break
                    except jwcrypto.jwk.InvalidJWKType:
                        continue
            else:
                raise RuntimeError('No EC Keys')

        elif jwk_algo == 'RS256':
            if not jwk_set:
                raise RuntimeError('No RSA Keys')

            for key in jwk_set:
                if key.key_type == 'RSA':
                    try:
                        payload = jwt.encode(
                            payload=payload,
                            key=key.export_to_pem(private_key=True, password=None),
                            algorithm='RS256',
                            headers={'kid': key.key_id}
                        )
                        break
                    except jwcrypto.jwk.InvalidJWKType:
                        continue
            else:
                raise RuntimeError('No RSA Keys')

        elif jwk_algo == 'HS256' or jwk_algo is None:
            payload = jwt.encode(payload=payload, key=self.secret, algorithm='HS256')
        elif jwk_algo == 'none':
            payload = jwt.encode(payload=payload, key=None, algorithm='none')
        else:
            raise Exception('Unsupported key algorithm {0}'.format(jwk_algo))

        if isinstance(payload, bytes):
            payload = payload.decode()

        return payload

    async def jws_sign(self, payload: Any, jwk_set: jwcrypto.jwk.JWKSet=None, algo: str=None) -> str:
        if not isinstance(payload, str):
            payload = jwcrypto.common.json_encode(payload)

        if jwk_set is None:
            jwk_set = self.jwk

        if algo == 'ES256':
            if not jwk_set:
                raise RuntimeError('No EC Keys')

            for key in jwk_set:
                if key.key_type == 'EC' and key._params.get('use', 'sig') == 'sig':
                    payload = jwcrypto.jws.JWS(payload)
                    payload.add_signature(key, None, {'alg': 'ES256'}, {'kid': key.key_id})
                    break
            else:
                raise RuntimeError('No EC Keys')

        elif algo == 'RS256':
            if not jwk_set:
                raise RuntimeError('No RSA Keys')

            for key in jwk_set:
                if key.key_type == 'RSA' and key._params.get('use', 'sig') == 'sig':
                    payload = jwcrypto.jws.JWS(payload)
                    payload.add_signature(key, None, {'alg': 'RS256'}, {'kid': key.key_id})
                    break
            else:
                raise RuntimeError('No RSA Keys')

        elif algo == 'HS256' or algo is None:
            payload = jwcrypto.jws.JWS(payload)
            payload.add_signature(self.secret, None, {'alg': 'HS256'})
        else:
            raise Exception('Unsupported key algorithm {0}'.format(algo))

        return payload.serialize(compact=True)

    async def jws_encrypt(self, payload: Any, alg: str, enc: str, jwk_set: jwcrypto.jwk.JWKSet=None) -> str:
        if alg == 'RSA1_5':
            key_type = 'RSA'
        else:
            raise RuntimeError('Unknown JWE alg {0}'.format(alg))

        # Look for client key to encrypt with
        if jwk_set is None:
            jwk_set = self.jwk
        for key in jwk_set:
            if key.key_type == key_type and key._params.get('use', 'enc') == 'enc':
                break
        else:
            raise RuntimeError('Could not find key for {0}'.format(key_type))

        payload = jwcrypto.jwe.JWE(
            jwcrypto.common.json_encode(payload),
            recipient=key,
            protected={'alg': alg, 'enc': enc, 'typ': 'JWE', 'kid': key.key_id}
        )

        return payload.serialize(compact=True)

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

    def serialise(self) -> Dict[str, Any]:
        result = {}

        for key, value in self.__dict__.items():
            if key in ('jwk',):
                continue
            result[key] = value

        result['jwk'] = self.jwk.export()

        return result

    @classmethod
    def deserialise(cls, data: Dict[str, Any]):
        if 'id' in data and 'id_' not in data:
            data['id_'] = data['id']
        if 'type' in data and 'type_' not in data:
            data['type_'] = data['type']
        return cls(**data)


class ClientStore(object):
    def __init__(self, provider=None):
        self._provider = provider

    def set_provider(self, provider):
        self._provider = provider

    async def setup(self):
        pass

    async def get_client_by_id(self, client_id: str) -> Union[Client, None]:
        raise NotImplementedError()

    async def get_client_by_access_token(self, access_token: str) -> Union[Client, None]:
        raise NotImplementedError()

    async def auth_client_registration(self, request: sanic.request.Request) -> bool:
        if 'authorization' not in request.headers:
            logger.warning('Client attempted registration without authorization header')
            return False

        hdr = request.headers['authorization']
        if 'Bearer' not in hdr:
            logger.warning('Client attempted registration without Bearer token')
            return False

        token = hdr.split('Bearer')[-1].strip()
        if self._provider.client_registration_key is None:
            return True
        elif isinstance(self._provider.client_registration_key, str) and self._provider.client_registration_key != token:
            logger.warning('Client attempted registration without incorrect Bearer token {0}'.format(masked(token)))
            return False
        elif inspect.iscoroutinefunction(self._provider.client_registration_key) and token != await self._provider.client_registration_key:
            logger.warning('Client attempted registration without incorrect Bearer token {0}'.format(masked(token)))
            return False

        return True




    async def validate_client(self, id_: str, name: str, secret: str, type_, callback_urls: Tuple[str, ...]) -> Tuple[bool, str]:
        logger.info('Validated client {0} - {1}'.format(id_, name))
        return True, ''

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
                         sector_identifier_uri: str=None,
                         userinfo_signed_response_alg: str=None,
                         userinfo_encrypted_response_alg: str=None,
                         userinfo_encrypted_response_enc: str=None,
                         logo_uri: str=None,
                         policy_uri: str=None,
                         tos_uri: str=None,

                         jwks: Dict[str, Any] = None
                         ) -> Tuple[bool, Union[str, Client]]:
        raise NotImplementedError()

    async def delete_client_by_id(self, client_id: str) -> bool:
        raise NotImplementedError()

    async def all(self) -> AsyncGenerator[Client, None]:
        if False:  # For typing
            yield Client()


class InMemoryClientStore(ClientStore):
    def __init__(self, *args, **kwargs):
        super(InMemoryClientStore, self).__init__(*args, **kwargs)

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
                         sector_identifier_uri: str=None,
                         userinfo_signed_response_alg: str=None,
                         userinfo_encrypted_response_alg: str = None,
                         userinfo_encrypted_response_enc: str = None,
                         logo_uri: str=None,
                         policy_uri: str=None,
                         tos_uri: str=None,

                         jwks: Dict[str, Any] = None
                         ) -> Tuple[bool, Union[str, Client]]:
        valid, err = await self.validate_client(id_, name, secret, type_, callback_urls)
        if not valid:
            return False, err

        client = Client(id_=id_,
                        name=name,
                        secret=secret,
                        type_=type_,
                        require_consent=require_consent,
                        reuse_consent=reuse_consent,
                        scopes=scopes,
                        callback_urls=callback_urls,
                        response_types=response_types,
                        jwt_algo=jwt_algo,
                        prompts=prompts,
                        application_type=application_type,
                        jwks_url=jwks_url,
                        post_logout_redirect_urls=post_logout_redirect_urls,
                        grant_types=grant_types,
                        contacts=contacts,
                        expires_at=expires_at,
                        sector_identifier_uri=sector_identifier_uri,
                        userinfo_signed_response_alg=userinfo_signed_response_alg,
                        request_urls=request_urls,
                        userinfo_encrypted_response_alg=userinfo_encrypted_response_alg,
                        userinfo_encrypted_response_enc=userinfo_encrypted_response_enc)

        await client.load_jwks(jwk_dict=jwks)

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

    async def all(self) -> AsyncGenerator[Client, None]:
        for client in self._clients.values():
            yield client


class DynamoDBClientStore(ClientStore):
    def __init__(self, *args, table_name: str='oidc-clients', region: str='eu-west-1', boto_config: Optional[Config]=None, **kwargs):
        super(DynamoDBClientStore, self).__init__(*args, **kwargs)

        # if 'HTTP_PROXY' in os.environ:
        #     app['boto_proxy_config'] = Config(proxies={'https': os.environ['HTTP_PROXY']})
        # elif 'HTTPS_PROXY' in os.environ:
        #     # aiohttp doesnt support https proxies
        #     app['boto_proxy_config'] = Config(proxies={'https': os.environ['HTTPS_PROXY'].replace('https', 'http')})
        # else:
        #     app['boto_proxy_config'] = None
        self._table_name = table_name
        self._region = region
        self._boto_config = boto_config
        self._dynamodb_resource = None
        self._table = None

    async def setup(self):
        self._dynamodb_resource = aioboto3.resource('dynamodb', region_name=self._region, config=self._boto_config)
        self._table = self._dynamodb_resource.Table(self._table_name)

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
                         sector_identifier_uri: str=None,
                         userinfo_signed_response_alg: str=None,
                         userinfo_encrypted_response_alg: str = None,
                         userinfo_encrypted_response_enc: str = None,
                         logo_uri: str=None,
                         policy_uri: str=None,
                         tos_uri: str=None,

                         jwks: Dict[str, Any]=None
                         ) -> Tuple[bool, Union[str, Client]]:
        valid, err = await self.validate_client(id_, name, secret, type_, callback_urls)
        if not valid:
            return False, err

        client = Client(id_=id_,
                        name=name,
                        secret=secret,
                        type_=type_,
                        require_consent=require_consent,
                        reuse_consent=reuse_consent,
                        scopes=scopes,
                        callback_urls=callback_urls,
                        response_types=response_types,
                        jwt_algo=jwt_algo,
                        prompts=prompts,
                        application_type=application_type,
                        jwks_url=jwks_url,
                        post_logout_redirect_urls=post_logout_redirect_urls,
                        grant_types=grant_types,
                        contacts=contacts,
                        expires_at=expires_at,
                        sector_identifier_uri=sector_identifier_uri,
                        userinfo_signed_response_alg=userinfo_signed_response_alg,
                        request_urls=request_urls,
                        userinfo_encrypted_response_alg=userinfo_encrypted_response_alg,
                        userinfo_encrypted_response_enc=userinfo_encrypted_response_enc)

        await client.load_jwks(jwk_dict=jwks)

        client_as_json = client.serialise()
        try:
            await self._table.put_item(Item=client_as_json)
            logger.info('Added client {0} - {1}'.format(id_, name))
            return True, client
        except Exception as err:
            logger.exception('Failed to add client {0} - {1}'.format(id_, name), exc_info=err)
            return False, 'unknown error'

    async def delete_client_by_id(self, client_id: str) -> bool:
        try:
            await self._table.delete_item(Key={'id': client_id})
            logger.info('Deleted client {0}'.format(client_id))
        except KeyError:
            pass
        return True

    async def get_client_by_id(self, client_id: str) -> Union[Client, None]:
        try:
            resp = await self._table.get_item(Key={'id': client_id})
            if 'Item' in resp:
                return Client.deserialise(resp['Item'])
        except KeyError:
            pass

        return None

    async def get_client_by_access_token(self, access_token: str) -> Union[Client, None]:

        resp = await self._table.scan(FilterExpression=Attr('access_token').eq(access_token))

        if resp['Count']:
            return Client.deserialise(resp['Items'][0])
        return None

    async def all(self) -> AsyncGenerator[Client, None]:
        resp = await self._table.scan()

        for client_data in resp.get('Items', []):
            client = Client.deserialise(client_data)
            yield client
