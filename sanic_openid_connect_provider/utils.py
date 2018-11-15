from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode

from sanic.request import Request
from sanic.response import HTTPResponse

if TYPE_CHECKING:
    from sanic_openid_connect_provider.provider import Provider


def get_scheme(request: Request) -> str:
    if 'X-Forwarded-Proto' in request.headers:
        scheme = request.headers['X-Forwarded-Proto']
    else:
        scheme = request.scheme

    return scheme


def get_provider(request: Request) -> 'Provider':
    return request.app.config['oicp_provider']


def redirect(url: str) -> HTTPResponse:
    """
    Expects the URL to already be safe. The sanic redirect quotes things again :(
    """
    return HTTPResponse(headers={'Location': url}, status=302)


def strip_prompt_login(path: str) -> str:
    """
    Strips 'login' from the 'prompt' query parameter.
    """
    uri = urlsplit(path)
    query_params = parse_qs(uri.query)
    prompt_list = query_params.get('prompt', '')[0].split()
    if 'login' in prompt_list:
        prompt_list.remove('login')
        query_params['prompt'] = ' '.join(prompt_list)
    if not query_params['prompt']:
        del query_params['prompt']
    uri = uri._replace(query=urlencode(query_params, doseq=True))
    return urlunsplit(uri)


def masked(value: Any) -> str:
    value = str(value)

    if len(value) > 6:
        return '********' + value[-3:]
    elif len(value) > 4:
        return '********' + value[-1:]
    else:
        return '********'
