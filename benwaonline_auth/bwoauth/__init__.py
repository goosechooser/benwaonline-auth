import os
from flask import Blueprint
from pymemcache.client.base import Client
from benwaonline_auth.config import app_config

cfg = app_config[os.getenv('FLASK_CONFIG')]
cache = Client((cfg.MEMCACHED_HOST, cfg.MEMCACHED_PORT), connect_timeout=5)

auth = Blueprint('auth', __name__)

from benwaonline_auth.bwoauth import views, core
