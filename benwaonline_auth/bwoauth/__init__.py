from flask import Blueprint
from werkzeug.contrib.cache import SimpleCache
from benwaonline_auth.models import Client

cache = SimpleCache()
auth = Blueprint('auth', __name__)

from benwaonline_auth.bwoauth import views, core
