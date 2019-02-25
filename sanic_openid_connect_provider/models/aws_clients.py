import logging
from typing import Tuple, Union, Dict, Optional, Any, AsyncGenerator

import aioboto3
from boto3.dynamodb.conditions import Attr
from botocore.config import Config

from sanic_openid_connect_provider.models.clients import ClientStore, Client

logger = logging.getLogger('oicp')


class DynamoDBClientStore(ClientStore):
    def __init__(self, *args, table_name: str = 'oidc-clients', region: str = 'eu-west-1',
                 boto_config: Optional[Config] = None, **kwargs):
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
                         require_consent: bool = False,
                         reuse_consent: bool = False,
                         scopes: Tuple[str, ...] = ('profile', 'email', 'phone'),
                         response_types: Tuple[str, ...] = ('code',),
                         jwt_algo: str = None,
                         prompts: Tuple[str, ...] = None,
                         application_type: str = None,
                         grant_types: Tuple[str, ...] = None,
                         contacts: Tuple[str, ...] = None,
                         expires_at: Optional[int] = None,
                         jwks_url: Tuple[str, ...] = None,
                         post_logout_redirect_urls: Tuple[str, ...] = None,
                         request_urls: Tuple[str, ...] = None,
                         sector_identifier_uri: str = None,
                         userinfo_signed_response_alg: str = None,
                         userinfo_encrypted_response_alg: str = None,
                         userinfo_encrypted_response_enc: str = None,
                         logo_uri: str = None,
                         policy_uri: str = None,
                         tos_uri: str = None,

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
