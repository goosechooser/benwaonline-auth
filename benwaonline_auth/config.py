import os
from datetime import timedelta

BASE = os.path.abspath(os.path.dirname(__file__))

def get_pem(fname):
    try:
        with open(fname, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return None

class Config(object):
    BASE_DIR = BASE
    DB_BASE_URI = 'mysql+pymysql://{}:{}@{}:{}/'.format(
        os.getenv('MYSQL_USER', 'root'),
        os.getenv('MYSQL_PASSWORD', 'root'),
        os.getenv('MYSQL_HOST', '192.168.10.11'),
        os.getenv('MYSQL_PORT', '3306')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'vsecret'
    TWITTER_CONSUMER_KEY = os.getenv('TWITTER_CONSUMER_KEY')
    TWITTER_CONSUMER_SECRET = os.getenv('TWITTER_CONSUMER_SECRET')
    ISSUER = 'issuer'
    API_AUDIENCE = 'api audience'
    REFRESH_TOKEN_LIFESPAN = timedelta(days=14)
    MEMCACHED_HOST = os.getenv('MEMCACHED_HOST', '192.168.10.11')
    MEMCACHED_PORT = int(os.getenv('MEMCACHED_PORT', 11211))

class DevConfig(Config):
    DB_NAME = os.getenv('DB_NAME', 'benwaonlineauth')
    SQLALCHEMY_DATABASE_URI = Config.DB_BASE_URI + DB_NAME
    DEBUG = True
    CLIENT_ID = 'nice'
    CLIENT_SECRET = 'ok'
    FRONT_URL_BASE = os.getenv('FRONT_URL_BASE', 'http://127.0.0.1:5000')
    AUTH_URL_BASE = os.getenv('AUTH_URL_BASE', 'http://127.0.0.1:5002')
    PRIVATE_KEY = get_pem('benwaauth_priv.pem')
    PUBLIC_KEY = get_pem('benwaauth_pub.pem')

class TestConfig(Config):
    DB_NAME = os.getenv('DB_NAME', 'benwaonlineauth_test')
    SQLALCHEMY_DATABASE_URI = Config.DB_BASE_URI + DB_NAME
    FRONT_URL_BASE = os.getenv('FRONT_URL_BASE', 'mock://mock-front')
    AUTH_URL_BASE = os.getenv('AUTH_URL_BASE')
    TESTING = True
    WTF_CSRF_ENABLED = False
    PRIVATE_KEY = get_pem('tests/data/benwaonline_auth_test_priv.pem')
    PUBLIC_KEY = get_pem('tests/data/benwaonline_auth_test_pub.pem')
    MEMCACHED_PORT = int(os.getenv('MEMCACHED_PORT', 11212))
    
class ProdConfig(Config):
    DB_BASE_URI = 'mysql+pymysql://{}:{}@{}:{}/'.format(
        os.getenv('MYSQL_USER'),
        os.getenv('MYSQL_PASSWORD'),
        os.getenv('MYSQL_HOST'),
        os.getenv('MYSQL_PORT')
    )
    SQLALCHEMY_DATABASE_URI = DB_BASE_URI + 'benwaonlineauth'
    DEBUG = False
    ISSUER = 'https://benwa.online'
    API_AUDIENCE = 'https://benwa.online/api'
    FRONT_URL_BASE = os.getenv('FRONT_URL_BASE')
    AUTH_URL_BASE = os.getenv('AUTH_URL_BASE')
    SECRET_KEY = os.getenv('SECRET_KEY_AUTH')
    PRIVATE_KEY = get_pem('benwaauth_priv.pem')
    PUBLIC_KEY = get_pem('benwaauth_pub.pem')

app_config = {
    'dev': DevConfig,
    'test': TestConfig,
    'prod': ProdConfig
}
