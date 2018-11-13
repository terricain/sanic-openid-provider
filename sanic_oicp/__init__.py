import uuid
import base64
import hashlib
import binascii
import datetime
import logging
from typing import Union, Tuple, Dict, Any, Type, Optional, List

import sanic.request

from sanic_oicp.handlers import well_known_config_handler, well_known_finger_handler, jwk_handler, userinfo_handler, client_register_handler
from sanic_oicp.authorize_endpoint import authorize_handler
from sanic_oicp.token_endpoint import token_handler
from sanic_oicp.utils import masked
from sanic_oicp.provider import Provider

from sanic_oicp.models.clients import ClientStore, InMemoryClientStore
from sanic_oicp.models.users import UserManager
from sanic_oicp.models.code import CodeStore, InMemoryCodeStore
from sanic_oicp.models.token import TokenStore, InMemoryTokenStore


logger = logging.getLogger('oicp')


def setup(app: sanic.Sanic,
          wellknown_config_path: str='/.well-known/openid-configuration',
          wellknown_finger_path: str='/.well-known/webfinger',
          jwk_path: str='/sso/oidc/jwk',  # TODO oidc -> oicp
          userinfo_path: str='/sso/oidc/userinfo',
          token_path: str='/sso/oidc/token',
          authorize_path: str='/sso/oidc/authorize',
          client_register_path: str='/sso/oidc/client_register',
          login_funcname='login',
          token_expire: int=86400,
          code_expire: int=86400,
          grant_type_password: bool=False,
          private_keys: List[str]=None,

          user_manager_class: Type[UserManager]=UserManager,
          client_manager_class: Type[ClientStore]=InMemoryClientStore,
          code_manager_class: Type[CodeStore]=InMemoryCodeStore,
          token_manager_class: Type[TokenStore]=InMemoryTokenStore
          ):

    app.add_route(well_known_config_handler, wellknown_config_path, frozenset({'GET'}))
    app.add_route(well_known_finger_handler, wellknown_finger_path, frozenset({'GET'}))
    app.add_route(jwk_handler, jwk_path, frozenset({'GET'}))
    app.add_route(userinfo_handler, userinfo_path, frozenset({'GET', 'POST'}))
    app.add_route(token_handler, token_path, frozenset({'POST'}))
    app.add_route(authorize_handler, authorize_path, frozenset({'GET', 'POST'}))
    app.add_route(client_register_handler, client_register_path, frozenset({'GET', 'POST'}))

    app.config['oicp_provider'] = Provider(
        user_manager_class=user_manager_class,
        client_manager_class=client_manager_class,
        code_manager_class=code_manager_class,
        token_manager_class=token_manager_class,

        login_function_name=login_funcname,
        token_expire_time=token_expire,
        code_expire_time=code_expire
    )
    app.config['oicp_provider'].load_keys(private_keys)

    # app.config['oicp_user'] = user_manager_class()
    # app.config['oicp_code'] = InMemoryCodeStore()
    # app.config['oicp_client'] = InMemoryClientStore()
    # app.config['oicp_token'] = InMemoryTokenStore()
    # app.config['oicp_login_funcname'] = login_funcname
    # app.config['oicp_token_expire'] = token_expire
    # app.config['oicp_code_expire'] = code_expire
    # app.config['oicp_grant_type_password'] = grant_type_password
