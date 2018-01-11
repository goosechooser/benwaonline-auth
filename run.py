import os

from benwaonline_auth import create_app

config_name = os.getenv('FLASK_CONFIG')
app = create_app(config_name)
