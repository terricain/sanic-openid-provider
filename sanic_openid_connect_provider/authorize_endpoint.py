import json
import logging
from typing import Dict, Any, Tuple, TYPE_CHECKING
from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode, unquote

import sanic.request
import sanic.response

from sanic_openid_connect_provider.exceptions import *
from sanic_openid_connect_provider.utils import strip_prompt_login, redirect, get_scheme, get_provider

if TYPE_CHECKING:
    from sanic_openid_connect_provider.provider import Provider


logger = logging.getLogger('oicp')


def get_request_url(request: sanic.request.Request) -> str:
    url = request.url
    scheme = get_scheme(request)
    if not url.startswith(scheme + ':'):
        url = scheme + ':' + url.split(':', 1)[-1]

    return url


async def create_authorize_response_params(request: sanic.request.Request, params: Dict[str, Any], user: Dict[str, Any]) -> Tuple[dict, dict]:
    provider = get_provider(request)
    client = params['client']

    uri = urlsplit(params['redirect_uri'])
    query_params = parse_qs(uri.query)
    query_fragment = {}

    try:
        if params['grant_type'] in ('authorization_code', 'hybrid'):
            code = await provider.codes.create_code(
                client=client,
                user=user,
                scopes=params['scopes'],
                code_expire=int(provider.code_expire_time),
                nonce=params['nonce'],
                code_challenge=params['code_challenge'],
                code_challenge_method=params['code_challenge_method'],
                specific_claims=params['specific_claims']
            )

        if params['grant_type'] == 'authorization_code':
            # noinspection PyUnboundLocalVariable
            query_params['code'] = code['code']
            query_params['state'] = params['state']

        elif params['grant_type'] in ['implicit', 'hybrid']:
            token = provider.tokens.create_token(
                user=user,
                client=client,
                auth_time=user['auth_time'],
                scope=params['scopes'],
                expire_delta=provider.token_expire_time,
                specific_claims=params['specific_claims']
            )

            # Check if response_type must include access_token in the response.
            if params['response_type'] in ('id_token token', 'token', 'code token', 'code id_token token'):
                query_fragment['access_token'] = token['access_token']

            # We don't need id_token if it's an OAuth2 request.
            if 'openid' in params['scopes']:
                scheme = get_scheme(request)
                issuer = '{0}://{1}'.format(scheme, request.host)

                kwargs = {
                    'auth_time': token['auth_time'],
                    'user': user,
                    'client': client,
                    'issuer': issuer,
                    'expire_delta': provider.token_expire_time,
                    'nonce': params['nonce'],
                    'at_hash': token['at_hash'],
                    'scope': params['scopes'],
                    'specific_claims': params['specific_claims']
                }
                # Include at_hash when access_token is being returned.
                if 'access_token' in query_fragment:
                    kwargs['at_hash'] = token['at_hash']
                id_token_dic = provider.tokens.create_id_token(**kwargs)

                # Check if response_type must include id_token in the response.
                if params['response_type'] in ('id_token', 'id_token token', 'code id_token', 'code id_token token'):

                    query_fragment['id_token'] = await client.sign(id_token_dic, jwk_set=provider.jwk_set)
            else:
                id_token_dic = {}

            # Store the token.
            token['id_token'] = id_token_dic
            await provider.tokens.save_token(token)

            # Code parameter must be present if it's Hybrid Flow.
            if params['grant_type'] == 'hybrid':
                # noinspection PyUnboundLocalVariable
                query_fragment['code'] = code['code']

            query_fragment['token_type'] = 'bearer'
            query_fragment['expires_in'] = provider.token_expire_time
            query_fragment['state'] = params['state']

    except Exception as err:
        logger.exception('Failed whilst creating authorize response', exc_info=err)
        raise AuthorizeError(params['redirect_uri'], 'server_error', params['grant_type'])

    query_params = {key: value for key, value in query_params.items() if value}
    query_fragment = {key: value for key, value in query_fragment.items() if value}

    return query_params, query_fragment


def create_authorize_response_uri(redirect_uri: str, query_params: Dict[str, Any], query_fragment: Dict[str, Any]) -> str:
    uri = urlsplit(redirect_uri)

    uri = uri._replace(
        query=urlencode(query_params, doseq=True),
        fragment=uri.fragment + urlencode(query_fragment, doseq=True))

    return urlunsplit(uri)


async def validate_authorize_params(request: sanic.request.Request, provider: 'Provider') -> Dict[str, Any]:
    if request.method == 'POST':
        req_dict = request.form
    else:
        req_dict = request.args

    # Check they provided a client_id
    if 'client_id' not in req_dict:
        logger.warning('client_id missing from request')
        raise ClientIdError()

    client_id = req_dict.get('client_id')
    client = await provider.clients.get_client_by_id(client_id)

    # Check client exists
    if not client:
        logger.warning('client {0} not found'.format(client_id))
        raise ClientIdError()

    # Check redirect URI is allowed
    redirect_uri = req_dict.get('redirect_uri')
    if not redirect_uri or redirect_uri not in client.callback_urls:
        logger.warning('redirect_uri {0} not valid for client {1}'.format(redirect_uri, client.name))
        raise RedirectUriError()

    # Check response_type is allowed
    response_type = req_dict.get('response_type')
    # Sort them so they're always in order
    if response_type:
        response_type = ' '.join(sorted(response_type.split(' ')))

    if response_type in ('code',):
        grant_type = 'authorization_code'
    elif response_type in ('id_token', 'id_token token', 'token'):
        grant_type = 'implicit'
    elif response_type in ('code token', 'code id_token', 'code id_token token'):
        grant_type = 'hybrid'
    else:
        grant_type = None

    if grant_type is None:
        logger.warning('grant_type missing for client {1}'.format(grant_type, client.name))
        raise AuthorizeError(redirect_uri, 'unsupported_response_type', grant_type)
    if not grant_type:
        logger.warning('grant_type {0} not valid for client {1}'.format(grant_type, client.name))
        raise AuthorizeError(redirect_uri, 'unsupported_response_type', grant_type)

    # Check scopes have required stuff
    scopes = unquote(req_dict.get('scope', '')).split()
    if 'openid' not in scopes and (grant_type == 'hybrid' or response_type in ('id_token', 'id_token token')):
        # Missing openid scope
        logger.warning('invalid_scopes {0} for client {1}'.format(scopes, client.name))
        raise AuthorizeError(redirect_uri, 'invalid_scope', grant_type)

    # Check more attributes
    nonce = req_dict.get('nonce')
    if 'openid' in scopes and grant_type == 'implicit' and not nonce:
        logger.warning('missing nonce')
        raise AuthorizeError(redirect_uri, 'invalid_request', grant_type)

    if 'openid' in scopes and response_type not in client.response_types:
        logger.warning('missing openid scope')
        raise AuthorizeError(redirect_uri, 'invalid_request', grant_type)

    code_challenge = req_dict.get('code_challenge')
    code_challenge_method = req_dict.get('code_challenge_method')
    if code_challenge and code_challenge_method not in ('plain', 'S256'):
        logger.warning('invalid code_challenge params')
        raise AuthorizeError(redirect_uri, 'invalid_request', grant_type)

    # Can provide requests for specific claims
    specific_claims = req_dict.get('claims')
    if specific_claims:
        try:
            specific_claims = json.loads(specific_claims)
        except Exception as err:
            logger.exception('Failed to load specific claims', exc_info=err)

    # Get prompts
    prompts = set(unquote(req_dict.get('prompt', '')).split())

    return {
        'client': client,
        'redirect_uri': redirect_uri,
        'grant_type': grant_type,
        'response_type': response_type,
        'scopes': scopes,
        'state': req_dict.get('state', ''),
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'nonce': nonce,
        'prompt': client.prompts & prompts,  # Reduce prompts to only which is allowed by the client
        'response_mode': req_dict.get('response_mode', ''),
        'max_age': req_dict.get('max_age'),
        'specific_claims': specific_claims
    }


async def authorize_handler(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    provider = get_provider(request)

    # TODO split out based on response_type

    try:
        params = await validate_authorize_params(request, provider)

        if await provider.users.is_authenticated(request):
            user = await provider.users.get_user(request)

            if 'login' in params['prompt']:
                if 'none' in params['prompt']:
                    # If login and none in prompt arg
                    logger.warning('login prompt along with none prompt')
                    raise AuthorizeError(params['redirect_uri'], 'login_required', params['grant_type'])
                else:
                    # If login is in prompt arg
                    request['session'].clear()
                    next_page = strip_prompt_login(get_request_url(request))
                    return redirect(request.app.url_for(provider.login_function_name, next=next_page))

            if 'select_account' in params['prompt']:
                if 'none' in params['prompt']:
                    logger.warning('select_account prompt along with none prompt')
                    raise AuthorizeError(params['redirect_uri'], 'account_selection_required', params['grant_type'])
                else:
                    request['session'].clear()
                    return redirect(request.app.url_for(provider.login_function_name, next=get_request_url(request)))

            if {'none', 'consent'} <= params['prompt']:  # Tests if both none and consent in prompt
                logger.warning('consent prompt along with none prompt')
                raise AuthorizeError(params['redirect_uri'], 'consent_required', params['grant_type'])

            implicit_flow_resp_types = {'id_token', 'id_token token'}
            allow_skipping_consent = (params['client'].type in ('public', 'pairwise')
                                      or params['response_type'] in implicit_flow_resp_types)

            if not params['client'].require_consent and allow_skipping_consent and 'consent' not in params['prompt']:
                # If you dont require consent, and consent is allowed to be skipped (aka type=confidential), and consent hasn't
                # been requested
                query_params, query_fragment = await create_authorize_response_params(request, params, user)

                if params['response_mode'] == 'form_post':
                    # We've been requested to auto-post form data
                    logger.info('skipped consent, doing form-autosubmit for {0}'.format(params['client'].name))
                    return await request.app.extensions['jinja2'].render_async(provider.autosubmit_html,
                                                                               request,
                                                                               form_url=params['redirect_uri'],
                                                                               query_params=query_params,
                                                                               query_fragment=query_fragment)
                else:
                    # Standard 302 redirect
                    logger.info('skipped consent, doing 302 redirect for {0}'.format(params['client'].name))
                    return redirect(create_authorize_response_uri(params['redirect_uri'], query_params, query_fragment))

            # We require consent
            if params['client'].reuse_consent:
                # Allowing prior consent to be reused
                if user['consent'] and allow_skipping_consent and 'consent' not in params['prompt']:
                    # If user has already given consent, and consent not requested
                    query_params, query_fragment = await create_authorize_response_params(request, params, user)

                    if params['response_mode'] == 'form_post':
                        # We've been requested to auto-post form data
                        logger.info('reusing consent, doing form-autosubmit for {0}'.format(params['client'].name))
                        return await request.app.extensions['jinja2'].render_async(provider.autosubmit_html,
                                                                                   request,
                                                                                   form_url=params['redirect_uri'],
                                                                                   query_params=query_params,
                                                                                   query_fragment=query_fragment)
                    else:
                        # Standard 302 redirect
                        logger.info('reusing consent, doing 302 redirect for {0}'.format(params['client'].name))
                        return redirect(create_authorize_response_uri(params['redirect_uri'], query_params, query_fragment))

            if 'none' in params['prompt']:
                # Return consent_required
                logger.info('none prompt, giving up')
                raise AuthorizeError(params['redirect_uri'], 'consent_required', params['grant_type'])

            # Generate hidden inputs for the form.
            hidden_params = {
                'client_id': params['client'].id,
                'redirect_uri': params['redirect_uri'],
                'grant_type': params['grant_type'],
                'response_type': params['response_type'],
                'scope': params['scopes'],
                'state': params['state'],
                'nonce': params['nonce'],
                'prompt': ' '.join(list(params['prompt'])),

            }
            if params['code_challenge']:
                hidden_params['code_challenge'] = params['code_challenge']
                hidden_params['code_challenge_method'] = params['code_challenge_method']
            if params['response_mode']:
                hidden_params['response_mode'] = params['response_mode']
            if params['max_age']:
                hidden_params['max_age'] = params['max_age']
            hidden_inputs = await request.app.extensions['jinja2'].render_string_async(provider.hidden_inputs_html, request, params=hidden_params)

            # Remove `openid` from scope list since we don't need to print it.
            try:
                params['scopes'].remove('openid')
            except ValueError:
                pass

            context = {
                'client_name': params['client'].name,
                'form_url': request.path,
                'hidden_inputs': hidden_inputs,
                'scopes': params['scopes'],
            }

            # Show authorize html page #TODO allow it to be customised
            logger.info('showing consent for {0}'.format(params['client'].name))
            return await request.app.extensions['jinja2'].render_async(provider.authorize_html, request, **context)

        else:
            # Not logged in
            if 'none' in params['prompt']:
                # Cant prompt, raise error
                logger.warning('Not logged in, prompt=none, error')
                raise AuthorizeError(params['redirect_uri'], 'login_required', params['grant_type'])

            logger.warning('Not logged in, redirecting to login page')

            if 'login' in params['prompt']:
                # Can prompt, redirect them to login page
                next_page = strip_prompt_login(get_request_url(request))
                return redirect(request.app.url_for(provider.login_function_name, next=next_page))

            # Nothing in prompt, so default to redirecting to login page
            return redirect(request.app.url_for(provider.login_function_name, next=get_request_url(request)))

    except (ClientIdError, RedirectUriError) as err:

        context = {'error': err.error, 'description': err.description}
        return await request.app.extensions['jinja2'].render_async(provider.error_html, request, **context)

    except AuthorizeError as err:

        if request.method == 'POST':
            req_dict = request.form
        else:
            req_dict = request.args

        state = req_dict.get('state')
        response_mode = req_dict.get('response_mode')

        if response_mode == 'form_post':
            return await request.app.extensions['jinja2'].render_async(
                provider.autosubmit_html,
                request,
                form_url=err.redirect_uri,
                query_params={'error': err.error, 'error_description': err.description},
                query_fragment={})
        else:
            uri = err.create_uri(err.redirect_uri, state)
            return redirect(uri)
