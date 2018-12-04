import inspect
import logging
from typing import List, Union, Type, Dict, Any, TypeVar, Coroutine

import jwcrypto.jwk

from sanic_openid_connect_provider.models.clients import ClientStore
from sanic_openid_connect_provider.models.code import CodeStore
from sanic_openid_connect_provider.models.token import TokenStore
from sanic_openid_connect_provider.models.users import UserManager

logger = logging.getLogger('oicp')
T = TypeVar('T')


class Provider(object):
    def __init__(self,
                 user_manager_class: Union[Type[UserManager], UserManager],
                 client_manager_class: Union[Type[ClientStore], ClientStore],
                 code_manager_class: Union[Type[CodeStore], CodeStore],
                 token_manager_class: Union[Type[TokenStore], TokenStore],

                 login_function_name: str='login',
                 token_expire_time: int=86400,
                 code_expire_time: int=86400,

                 allow_grant_type_password: bool=False,
                 open_client_registration: bool = True,
                 client_registration_key: Union[str, None, Coroutine[str, None, bool]] = None,

                 error_html: str = 'error.html',
                 autosubmit_html: str = 'form-autosubmit.html',
                 hidden_inputs_html: str = 'hidden_inputs.html',
                 authorize_html: str = 'authorize.html'
                 ):

        self.jwk_set = jwcrypto.jwk.JWKSet()

        self.users: UserManager = self._class_or_object(user_manager_class)
        self.clients: ClientStore = self._class_or_object(client_manager_class)
        self.codes: CodeStore = self._class_or_object(code_manager_class)
        self.tokens: TokenStore = self._class_or_object(token_manager_class)

        self.login_function_name = login_function_name
        self.token_expire_time = token_expire_time
        self.code_expire_time = code_expire_time

        self.allow_grant_type_password = allow_grant_type_password
        self.open_client_registration = open_client_registration
        self.client_registration_key = client_registration_key

        self.error_html = error_html
        self.autosubmit_html = autosubmit_html
        self.hidden_inputs_html = hidden_inputs_html
        self.authorize_html = authorize_html

    async def setup(self):
        await self.users.setup()
        await self.clients.setup()
        await self.codes.setup()
        await self.tokens.setup()

    def _class_or_object(self, obj: Union[Type[T], T]) -> T:
        if inspect.isclass(obj):
            inst = obj(provider=self)
        else:
            inst = obj
            inst.set_provider(self)
        return inst

    def load_keys(self, keys: List[Union[str, jwcrypto.jwk.JWK]]=None):
        """
        Takes a list of keys or paths to pem encoded certificates
        """
        if keys:
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
