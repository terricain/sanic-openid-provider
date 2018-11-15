import base64
import hashlib
import json
import logging
from typing import Dict, Any

import jwt
import sanic.request
import sanic.response

from sanic_openid_connect_provider.exceptions import TokenError, UserAuthError
from sanic_openid_connect_provider.utils import get_scheme, get_provider

logger = logging.getLogger('oicp')


async def create_refresh_response_dic(request: sanic.request.Request, params: Dict[str, Any]) -> Dict[str, Any]:
    provider = get_provider(request)
    # See https://tools.ietf.org/html/rfc6749#section-6

    scope_param = params['scope']
    scope = (scope_param if scope_param else params['token_obj']['scope'])
    unauthorized_scopes = set(scope) - set(params['token_obj']['scope'])
    if unauthorized_scopes:
        raise TokenError('invalid_scope')

    user = await provider.users.get_user_by_username(params['token_obj']['user'])
    client = params['client']

    token = provider.tokens.create_token(
        user=user,
        client=client,
        scope=scope,
        auth_time=params['token_obj']['auth_time'],
        specific_claims=params['specific_claims'],
        expire_delta=provider.token_expire_time
    )

    scheme = get_scheme(request)
    issuer = '{0}://{1}'.format(scheme, request.host)

    # If the Token has an id_token it's an Authentication request.
    if params['token_obj']['id_token']:
        id_token_dic = provider.tokens.create_id_token(
            user=user,
            auth_time=token['auth_time'],
            issuer=issuer,
            client=client,
            nonce=None,
            expire_delta=provider.token_expire_time,
            at_hash=token['at_hash'],
            scope=token['scope'],
            specific_claims=token['specific_claims']
        )
    else:
        id_token_dic = {}

    token['id_token'] = id_token_dic
    await provider.tokens.save_token(token)
    await provider.tokens.delete_token_by_access_token(params['token_obj']['access_token'])

    id_token = await client.sign(id_token_dic, jwk_set=provider.jwk_set)

    dic = {
        'access_token': token['access_token'],
        'refresh_token': token['refresh_token'],
        'token_type': 'bearer',
        'expires_in': provider.token_expire_time,
        'id_token': id_token,
    }

    return dic


async def create_code_response_dic(request: sanic.request.Request, params: Dict[str, Any]) -> Dict[str, Any]:
    provider = get_provider(request)
    # See https://tools.ietf.org/html/rfc6749#section-4.1

    user = await provider.users.get_user_by_username(params['code_obj']['user'])
    client = params['client']

    token = provider.tokens.create_token(
        user=user,
        client=client,
        auth_time=params['code_obj']['auth_time'],
        scope=params['code_obj']['scope'],
        expire_delta=provider.token_expire_time,
        specific_claims=params['code_obj']['specific_claims'],
        code=params['code']
    )

    scheme = get_scheme(request)
    issuer = '{0}://{1}'.format(scheme, request.host)

    id_token_dic = provider.tokens.create_id_token(
        user=user,
        auth_time=token['auth_time'],
        client=client,
        issuer=issuer,
        expire_delta=provider.token_expire_time,
        nonce=params['code_obj']['nonce'],
        at_hash=token['at_hash'],
        scope=token['scope'],
        specific_claims=token['specific_claims']
    )

    token['id_token'] = id_token_dic
    await provider.tokens.save_token(token)
    await provider.codes.mark_used_by_id(params['code'])

    id_token = await client.sign(
        id_token_dic,
        jwk_set=provider.jwk_set
    )

    dic = {
        'access_token': token['access_token'],
        'refresh_token': token['refresh_token'],
        'token_type': 'bearer',
        'expires_in': provider.token_expire_time,
        'id_token': id_token,
    }

    return dic


async def validate_token_params(request: sanic.request.Request) -> Dict[str, Any]:
    provider = get_provider(request)

    if request.method == 'POST':
        req_dict = request.form
    else:
        req_dict = request.args

    client_assertion_type = req_dict.get('client_assertion_type')
    client_assertion = req_dict.get('client_assertion')

    if client_assertion_type and client_assertion_type == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer':
        header = jwt.get_unverified_header(client_assertion)
        audience = '{0}://{1}{2}'.format(get_scheme(request), request.host, request.path)

        # TODO maintain central collection of client jwts
        if 'kid' in header:
            # Asymetric signing
            temp_jwt_token = jwt.decode(client_assertion, verify=False)
            client = await provider.clients.get_client_by_id(temp_jwt_token['sub'])
            jwt_key = client.jwk.get_key(header.get('kid'))

            try:
                jwt.decode(client_assertion, jwt_key.export_to_pem(), algorithms=[header['alg']], audience=audience)
                # By it not erroring, its successfully verified
            except Exception as err:
                logger.exception('Invalid key id', exc_info=err)
                raise TokenError('invalid_client')

        else:
            # HMAC with client secret
            temp_jwt_token = jwt.decode(client_assertion, verify=False)
            client = await provider.clients.get_client_by_id(temp_jwt_token['sub'])

            try:
                jwt.decode(client_assertion, client.secret, algorithms=[header['alg']], audience=audience)
                # By it not erroring, its successfully verified
            except Exception as err:
                logger.exception('Invalid key id', exc_info=err)
                raise TokenError('invalid_client')

    else:
        client_id = req_dict.get('client_id')
        client_secret = req_dict.get('client_secret', '')
        if 'authorization' in request.headers and not client_id:
            hdr = request.headers['authorization']
            if 'Basic' in hdr:
                client_id, client_secret = base64.b64decode(hdr.split()[-1].encode()).decode().split(':')
            else:
                raise NotImplementedError(hdr)

        client = await provider.clients.get_client_by_id(client_id)
        if not client_id:
            raise TokenError('invalid_client')

    if not client:
        raise TokenError('invalid_client')

    specific_claims = req_dict.get('claims')
    if specific_claims:
        try:
            specific_claims = json.loads(specific_claims)
        except Exception as err:
            logger.exception('Failed to decode specific claims', exc_info=err)

    result = {
        'client': client,
        'grant_type': req_dict.get('grant_type', ''),
        'code': req_dict.get('code', ''),
        'state': req_dict.get('state', ''),
        'scope': req_dict.get('scope', ''),
        'redirect_uri': req_dict.get('redirect_uri', ''),
        'refresh_token': req_dict.get('refresh_token', ''),
        'code_verifier': req_dict.get('code_verifier'),
        'username': req_dict.get('username', ''),
        'password': req_dict.get('password', ''),
        'specific_claims': specific_claims

    }

    # if client.type == 'confidential' and client_secret != client.secret:
    #     raise TokenError('invalid_client')

    if result['grant_type'] == 'authorization_code':
        if result['redirect_uri'] not in client.callback_urls:
            raise TokenError('invalid_client')

        code = await provider.codes.get_by_id(result['code'])

        if not code:
            raise TokenError('invalid_grant')

        if code['used']:
            await provider.tokens.delete_token_by_code(result['code'])
            raise TokenError('invalid_grant')

        if code['client'] != client.id:
            raise TokenError('invalid_grant')

        if result['code_verifier']:
            if code['code_challenge_method'] == 'S256':
                new_code_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(result['code_verifier'].encode('ascii')).digest()
                ).decode('utf-8').replace('=', '')
            else:
                new_code_challenge = result['code_verifier']

            if new_code_challenge != code['code_challenge']:
                raise TokenError('invalid_grant')

        result['code_obj'] = code

    elif result['grant_type'] == 'password':
        if not provider.allow_grant_type_password:
            raise TokenError('unsupported_grant_type')

        # TODO authenticate username/password
        # result['username'] result['password']
        user = False

        if not user:
            raise UserAuthError()

        result['user_obj'] = user

    elif result['grant_type'] == 'client_credentials':
        # TODO not sure about this
        raise NotImplementedError()

    elif result['grant_type'] == 'refresh_token':
        if not result['refresh_token']:
            logger.warning('No refresh token')
            raise TokenError('invalid_grant')

        token = await provider.tokens.get_token_by_refresh_token(result['refresh_token'])
        if not token:
            raise TokenError('invalid_grant')

        result['token_obj'] = token

    return result


async def token_handler(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    try:
        params = await validate_token_params(request)

        if params['grant_type'] == 'authorization_code':
            payload = await create_code_response_dic(request, params)
        elif params['grant_type'] == 'refresh_token':
            payload = await create_refresh_response_dic(request, params)
        # elif params['grant_type'] == 'password':
        #     payload = create_access_token_response_dic(request, params)
        # elif params['grant_type'] == 'client_credentials':
        #     payload = create_client_credentials_response_dic(request, params)
        else:
            raise TokenError('invalid_grant')

        return sanic.response.json(payload)

    except TokenError as error:
        return sanic.response.json(error.create_dict(), status=400)
    except UserAuthError as error:
        return sanic.response.json(error.create_dict(), status=400)
