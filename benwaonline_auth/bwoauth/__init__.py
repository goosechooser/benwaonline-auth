import os
from flask import Blueprint
from werkzeug.contrib.cache import SimpleCache
from pymemcache.client.base import Client
# from benwaonline_auth.models import Client

if os.getenv('FLASK_CONFIG') == 'prod':
    addr = os.getenv('MEMCACHED_ADDR')
    cache = Client([addr])
else:
    cache = SimpleCache()

auth = Blueprint('auth', __name__)

from benwaonline_auth.bwoauth import views, core
