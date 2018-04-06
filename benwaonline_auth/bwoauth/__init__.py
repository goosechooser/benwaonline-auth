from flask import Blueprint
from werkzeug.contrib.cache import SimpleCache

cache = SimpleCache()
auth = Blueprint('auth', __name__)

from benwaonline_auth.bwoauth import views, core
