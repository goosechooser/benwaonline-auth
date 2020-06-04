import os
import json
from flask import Blueprint

auth = Blueprint("auth", __name__)

from benwaonline_auth.bwoauth import views, core
