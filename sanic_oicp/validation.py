from typing import Dict, Any

from sanic.request import Request

from sanic_oicp.exceptions import *


async def validate_userinfo_params(request: Request) -> Dict[str, Any]:
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

    token = await request.app.config['oicp_token'].get_token_by_access_token(access_token)
    if not token:
        raise TokenError('invalid_grant')

    result = {
        'token': token,
    }

    return result

