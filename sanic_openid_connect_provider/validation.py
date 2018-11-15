from typing import Dict, Any

from sanic.request import Request

from sanic_openid_connect_provider.exceptions import *
from sanic_openid_connect_provider.utils import get_provider


async def validate_userinfo_params(request: Request) -> Dict[str, Any]:
    provider = get_provider(request)

    if request.method == 'POST':
        req_dict = request.form
    else:
        req_dict = request.args

    access_token = None
    if 'authorization' in request.headers:
        hdr = request.headers['authorization']
        if 'Bearer' in hdr:
            access_token = hdr.split()[-1]
        else:
            raise NotImplementedError(hdr)

    if 'access_token' in req_dict:
        access_token = req_dict.get('access_token')

    if not access_token:
        raise TokenError('invalid_grant')

    token = await provider.tokens.get_token_by_access_token(access_token)
    if not token:
        raise TokenError('invalid_grant')

    result = {
        'token': token,
    }

    return result

