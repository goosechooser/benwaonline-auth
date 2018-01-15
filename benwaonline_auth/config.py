import os
from datetime import timedelta

BASE = os.path.abspath(os.path.dirname(__file__))

def get_pem(fname):
    try:
        with open(fname, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return None

def get_secret(secret_name):
    '''Returns value provided by a docker secret, otherwise returns env'''
    try:
        with open('/run/secrets/' + secret_name, 'r') as f:
            data = f.read()
            return data.strip()
    except OSError:
        return os.getenv(secret_name)

class Config(object):
    BASE_DIR = BASE
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'vsecret'
    TWITTER_CONSUMER_KEY = os.getenv('TWITTER_CONSUMER_KEY')
    TWITTER_CONSUMER_SECRET = os.getenv('TWITTER_CONSUMER_SECRET')
    ISSUER = 'issuer'
    API_AUDIENCE = 'api audience'
    REFRESH_TOKEN_LIFESPAN = timedelta(days=14)

class DevConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:root@localhost:3306/benwaonlineauth'
    DEBUG = True
    CLIENT_ID = 'nice'
    CLIENT_SECRET = 'ok'
    PRIVATE_KEY = get_pem('benwaauth_priv.pem')
    PUBLIC_KEY = get_pem('benwaauth_pub.pem')

class TestConfig(Config):
    DB_BASE_URI = 'mysql+pymysql://{}:{}@{}:{}/'.format(
        os.getenv('MYSQL_USER', 'root'),
        os.getenv('MYSQL_PASSWORD', ''),
        os.getenv('MYSQL_HOST', '127.0.0.1'),
        os.getenv('MYSQL_PORT', '3306')
    )

    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI = DB_BASE_URI + 'benwaonlineauth_test'
    AUTH_URL_BASE = os.getenv('AUTH_URL_BASE')
    TESTING = True
    WTF_CSRF_ENABLED = False
    PRIVATE_KEY = get_pem('tests/data/benwaonline_auth_test_priv.pem')
    PUBLIC_KEY = get_pem('tests/data/benwaonline_auth_test_pub.pem')

class ProdConfig(Config):
    DB_BASE_URI = 'mysql+pymysql://{}:{}@{}:{}/'.format(
        get_secret('MYSQL_USER'),
        get_secret('MYSQL_PASSWORD'),
        os.getenv('MYSQL_HOST'),
        os.getenv('MYSQL_PORT')
    )
    SQLALCHEMY_DATABASE_URI = DB_BASE_URI + 'benwaonlineauth'
    DEBUG = False
    ISSUER = 'https://benwa.online'
    API_AUDIENCE = 'https://benwa.online/api'
    AUTH_URL_BASE = os.getenv('AUTH_URL_BASE')
    SECRET_KEY = os.getenv('SECRET_KEY_AUTH')
    CLIENT_ID = os.getenv('BENWA_CONSUMER_KEY')
    CLIENT_SECRET = os.getenv('BENWA_SECRET_KEY')
    PRIVATE_KEY = get_pem('benwaauth_priv.pem')
    PUBLIC_KEY = get_pem('benwaauth_pub.pem')

app_config = {
    'dev': DevConfig,
    'test': TestConfig,
    'prod': ProdConfig
}
