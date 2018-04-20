import os
import logging
from benwaonline_auth import create_app

config_name = os.getenv('FLASK_CONFIG')
app = create_app(config_name)

if os.getenv('FLASK_CONFIG') == 'prod':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)