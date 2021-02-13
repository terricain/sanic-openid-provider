import os
import logging
import json

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

# listening on 8006 so login redirect is http://localhost:8006/callback - needs to be configured in okta
# Okta supports .well-known/openid-configuration
# https://OKTA_BASE/oauth2/default/.well-known/openid-configuration - look here for options
oicp_client = setup_client(
    app=app,
    callback_path='/callback',
    client_id=os.environ['OKTA_CLIENT_ID'],
    client_secret=os.environ['OKTA_CLIENT_SECRET'],
    signature_type='RS256',  # Okta only supports RS256
    autodiscover_base=os.environ['OKTA_BASE'],
    scopes=('openid', 'profile', 'email')
)


@app.route('/secret', methods=['GET'])
@oicp_client.login_required()
async def secret(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    return sanic.response.text('secret page:\n{0}'.format(json.dumps(dict(request.ctx.session))))


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
