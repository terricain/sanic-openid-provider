import datetime
import os
import logging
import json

import sanic.request
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

res_dir = os.path.join(os.path.dirname(__file__), 'resources')

oicp_client = setup_client(
    app=app,
    client_id='kbyuFDidLLm280LIwVFiazOqjO3ty8KH',
    client_secret='60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa',
    signature_type='ES256',
    autodiscover_base='http://localhost:8005'
)



@app.route('/secret', methods=['GET'])
@oicp_client.login_required()
async def secret(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    return sanic.response.text('secret page:\n{0}'.format(json.dumps(dict(request['session']))))


@app.route('/', methods=['GET'])
async def index(request: sanic.request.Request) -> sanic.response.BaseHTTPResponse:
    return sanic.response.html('<html><body>Homepage, secret page: <a href="{0}">/secret</a></body></html>'.format(app.url_for('secret')))


@app.listener('before_server_start')
async def startup(app, loop):
    await oicp_client.setup()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8006)
