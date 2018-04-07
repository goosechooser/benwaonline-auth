import os
import logging
from benwaonline_auth import create_app

config_name = os.getenv('FLASK_CONFIG')
app = create_app(config_name)

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)