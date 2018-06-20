import os

def get_pem(fname):
    try:
        with open(fname, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return None

class Config(object):
    DB_BASE_URI = 'mysql+pymysql://{}:{}@{}:{}/'.format(
        os.getenv('MYSQL_USER'),
        os.getenv('MYSQL_PASSWORD'),
        os.getenv('MYSQL_HOST'),
        os.getenv('MYSQL_PORT')
    )
    DB_NAME = os.getenv('DB_NAME')
    SQLALCHEMY_DATABASE_URI = DB_BASE_URI + DB_NAME

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY_AUTH')
    ISSUER = 'issuer'
    API_AUDIENCE = 'api audience'
    REDIS_HOST = os.getenv('REDIS_HOST')
    REDIS_PORT = os.getenv('REDIS_PORT')
    FRONT_URL = os.getenv('FRONT_HOST')
    AUTH_HOST = os.getenv('AUTH_HOST')
    AUTH_URL = '{}:{}'.format(os.getenv('AUTH_HOST'), os.getenv('AUTH_PORT', ''))
    PRIVATE_KEY = get_pem(os.getenv('PRIVATE_KEY'))
    PUBLIC_KEY = get_pem(os.getenv('PUBLIC_KEY'))

    TWITTER = {
        'consumer_key': os.getenv('TWITTER_CONSUMER_KEY'),
        'consumer_secret': os.getenv('TWITTER_CONSUMER_SECRET'),
        'base_url': 'https://api.twitter.com',
        'request_token_url': 'oauth/request_token',
        'access_token_url': 'oauth/access_token',
        'authorize_url': 'oauth/authenticate'
    }

class DevConfig(Config):
    CLIENT_ID = 'nice'
    CLIENT_SECRET = 'ok'

class TestConfig(Config):
    DB_NAME = 'benwaonlineauth_test'
    SQLALCHEMY_DATABASE_URI = Config.DB_BASE_URI + DB_NAME
    FRONT_URL = 'mock://mock-front'
    # AUTH_URL = os.getenv('AUTH_URL')
    TESTING = True
    WTF_CSRF_ENABLED = False
    PRIVATE_KEY = get_pem('tests/data/benwaonline_auth_test_priv.pem')
    PUBLIC_KEY = get_pem('tests/data/benwaonline_auth_test_pub.pem')

class ProdConfig(Config):
    DB_BASE_URI = 'mysql+pymysql://{}:{}@{}:{}/'.format(
        os.getenv('MYSQL_USER'),
        os.getenv('MYSQL_PASSWORD'),
        os.getenv('MYSQL_HOST'),
        os.getenv('MYSQL_PORT')
    )
    DB_NAME = os.getenv('DB_NAME')
    SQLALCHEMY_DATABASE_URI = DB_BASE_URI + DB_NAME
    ISSUER = 'https://benwa.online'
    API_AUDIENCE = 'https://benwa.online/api'

app_config = {
    'development': DevConfig,
    'testing': TestConfig,
    'production': ProdConfig
}
