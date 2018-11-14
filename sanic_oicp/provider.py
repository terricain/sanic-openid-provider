import logging
import jwcrypto.jwk
from typing import List, Union, Type, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from sanic_oicp.models.users import UserManager
    from sanic_oicp.models.clients import ClientStore
    from sanic_oicp.models.code import CodeStore
    from sanic_oicp.models.token import TokenStore


logger = logging.getLogger('oicp')


class Provider(object):
    def __init__(self,
                 user_manager_class: Type['UserManager'],
                 client_manager_class: Type['ClientStore'],
                 code_manager_class: Type['CodeStore'],
                 token_manager_class: Type['TokenStore'],

                 login_function_name: str='login',
                 token_expire_time: int=86400,
                 code_expire_time: int=86400,

                 allow_grant_type_password: bool=False):

        self.jwk_set = jwcrypto.jwk.JWKSet()

        self.users: 'UserManager' = user_manager_class(provider=self)
        self.clients: 'ClientStore' = client_manager_class(provider=self)
        self.codes: 'CodeStore' = code_manager_class(provider=self)
        self.tokens: 'TokenStore' = token_manager_class(provider=self)

        self.login_function_name = login_function_name
        self.token_expire_time = token_expire_time
        self.code_expire_time = code_expire_time

        self.allow_grant_type_password = allow_grant_type_password

    async def setup(self):
        await self.users.setup()
        await self.clients.setup()
        await self.codes.setup()
        await self.tokens.setup()

    def load_keys(self, keys: List[Union[str, jwcrypto.jwk.JWK]]=None):
        """
        Takes a list of keys or paths to pem encoded certificates
        """
        for key in keys:
            if isinstance(key, jwcrypto.jwk.JWK):
                self.jwk_set.add(key)
                logger.info('Added {0} key {1}'.format(key.key_type, key.key_id))
            else:
                pem = open(key, 'rb').read()

                jwk_obj = jwcrypto.jwk.JWK.from_pem(pem)
                self.jwk_set.add(jwk_obj)
                logger.info('Added {0} key {1}'.format(jwk_obj.key_type, jwk_obj.key_id))

    def handle_finger(self, resource: str, rel: str, issuer: str, finger_url: str) -> Dict[str, Any]:
        if resource == finger_url and rel == 'http://openid.net/specs/connect/1.0/issuer':
            result = {"subject": resource, "links": [{"rel": rel, "href": issuer}]}
        elif resource.startswith('acct:') and rel == 'http://openid.net/specs/connect/1.0/issuer':
            result = {"subject": resource, "links": [{"rel": rel, "href": issuer}]}
        else:
            result = {"subject": resource, "links": []}

        return result

