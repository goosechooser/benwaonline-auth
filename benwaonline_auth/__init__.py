import logging
import os

import yaml
from flask import (Flask, current_app, flash, g, json, jsonify, redirect,
                   request, url_for)
from oauthlib.oauth2.rfc6749.utils import list_to_scope, scope_to_list
from sqlalchemy import create_engine

from benwaonline_auth import config, models
from benwaonline_auth.bwoauth import auth
from benwaonline_auth.cache import cache
from benwaonline_auth.database import db
from benwaonline_auth.oauth import oauth

with open('jwks.json', 'r') as f:
    JWKS = json.load(f)

def setup_logger_handlers(app):
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s '
    '[in %(pathname)s:%(lineno)d]'
    ))
    sh.setLevel(logging.DEBUG)
    app.logger.addHandler(sh)

def create_app(config_name=None):
    """
    Returns the Flask app.
    """
    app = Flask(__name__)

    if not config_name:
        config_name = os.getenv('FLASK_ENV')

    if config_name == 'production':
        setup_logger_handlers(app)

    app.config.from_object(config.app_config[config_name])

    db.init_app(app)
    oauth.init_app(app)
    cache.init_app(app, config={
        'CACHE_TYPE': 'redis',
        'CACHE_DEFAULT_TIMEOUT': 5,
        'CACHE_REDIS_HOST': os.getenv('REDIS_HOST'),
        'CACHE_REDIS_PORT': os.getenv('REDIS_PORT'),
        'CACHE_KEY_PREFIX': 'benwaonline-auth:'
    })

    app.register_blueprint(auth)

    @app.cli.command()
    def initdb():
        '''Initialize the database.'''
        init_db(app)
        permissions = permissions_loader('benwaonline_auth/scopes.yml')
        init_clients(app, db.session, permissions)

    if config_name != 'prod':
        @app.route('/.well-known/jwks.json')
        def jwks():
            return jsonify(JWKS), 200

    return app

def init_db(app):
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    # 20$ says I run this on production
    engine.execute('DROP DATABASE benwaonlineauth')
    engine.execute('CREATE DATABASE benwaonlineauth')
    engine.execute('USE benwaonlineauth')

    import benwaonline_auth.models
    db.create_all()

# need a better way to pull all this info
# refactor this to a click script tbh
def init_clients(app, session, default_scopes=None):
    scopes = default_scopes or ['ham', 'eggs']
    client = models.Client(
        name='BenwaOnline',
        client_id=app.config['CLIENT_ID'],
        client_secret=app.config['CLIENT_SECRET'],
        grant_type='authorization_code',
        response_type='code',
        _redirect_uris='http://127.0.0.1:5000/authorize/callback',
        default_scopes=list_to_scope(scopes),
        allowed_scopes=list_to_scope(scopes)
    )
    session.add(client)
    session.commit()

    return

def permissions_loader(fpath):
    with open(fpath, 'r') as f:
        settings = yaml.load(f)

    resources = settings['resources']

    permissions = []
    for k, v in resources.items():
        permissions.extend([k + ':' + p for p in v['permissions']])

    return permissions
