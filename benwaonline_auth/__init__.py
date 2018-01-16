import json
import logging
from marshmallow import pprint
from flask import Flask, g, url_for, request, flash, redirect, jsonify
from sqlalchemy import create_engine

from benwaonline_auth.oauth import oauth
from benwaonline_auth.config import app_config
from benwaonline_auth.database import db
from benwaonline_auth.bwoauth import auth
from benwaonline_auth import models

with open('jwks.json', 'r') as f:
    JWKS = json.load(f)

def setup_logger_handlers(logger):
    fh = logging.FileHandler(__name__ +'_debug.log')
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

def create_app(config_name=None):
    """
    Returns the Flask app.
    """
    app = Flask(__name__)
    setup_logger_handlers(app.logger)
    app.config.from_object(app_config[config_name])

    db.init_app(app)
    oauth.init_app(app)
    app.register_blueprint(auth)

    @app.cli.command()
    def initdb():
        '''Initialize the database.'''
        init_db(app)
        init_clients(app, db.session)

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
def init_clients(app, session):
    client = models.Client(
        name='BenwaOnline',
        client_id=app.config['CLIENT_ID'],
        client_secret=app.config['CLIENT_SECRET'],
        response_type='code',
        _redirect_uris='http://127.0.0.1:5000/authorize/callback',
        default_scopes='ham eggs'
    )
    session.add(client)
    session.commit()

    return