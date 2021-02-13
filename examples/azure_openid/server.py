import os
import logging
import json

import aiohttp
import sanic.request
import sanic.exceptions
import sanic.response
from sanic_jinja2 import SanicJinja2
from sanic_session import Session, InMemorySessionInterface
from jinja2 import FileSystemLoader

from sanic_openid_connect_provider import setup_client

oicp_logger = logging.getLogger('oicp')
oicp_logger.setLevel(logging.INFO)
oicp_logger.addHandler(logging.StreamHandler())

app = sanic.Sanic()
session = Session(app, interface=InMemorySessionInterface())
jinja = SanicJinja2(app, loader=FileSystemLoader('./templates'), enable_async=True)

oicp_client = setup_client(
    app=app,
    callback_path='/callback',
    client_id=os.environ['AZURE_CLIENT_ID'],
    client_secret=os.environ['AZURE_CLIENT_SECRET'],
    signature_type='RS256',  # Azure only supports RS256
    autodiscover_base=os.environ['AZURE_BASE'],
    scopes=('openid', 'profile', 'email', 'User.Read')
)


@app.route('/secret', methods=['GET'])
@oicp_client.login_required()
async def secret(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    user_session = dict(request.ctx.session)

    # Microsoft graph
    url = 'https://graph.microsoft.com/v1.0/users/' + user_session['user']['oid']
    headers = {'Authorization': 'Bearer ' + user_session['user']['access_token'],
               'Content-Type': 'application/json'}

    async with aiohttp.ClientSession() as sesh:
        async with sesh.get(url, headers=headers) as resp:
            body = await resp.json()

    return sanic.response.text('secret page:\n{0}\n\nUser data: {1}\n'.format(json.dumps(user_session, indent=2), json.dumps(body, indent=2)))


@app.route('/', methods=['GET'])
async def index(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    return sanic.response.html('<html><body>Homepage, secret page: <a href="{0}">/secret</a></body></html>'.format(app.url_for('secret')))


@app.exception(sanic.exceptions.NotFound)
async def ignore_404s(request, exception):
    return sanic.response.text('', status=404)


@app.listener('before_server_start')
async def startup(app, loop):
    await oicp_client.setup()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8006)
