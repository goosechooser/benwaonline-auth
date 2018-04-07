import os
import json

from pymemcache.client.base import Client

from benwaonline_auth.config import app_config

cfg = app_config[os.getenv('FLASK_CONFIG')]

def json_serializer(key, value):
    if type(value) == str:
        return value, 1
    return json.dumps(value), 2

def json_deserializer(key, value, flags):
    if flags == 1:
        return value.decode('utf-8')
    if flags == 2:
        return json.loads(value.decode('utf-8'))
    raise Exception("Unknown serialization format")

cache = Client(
    (cfg.MEMCACHED_HOST, cfg.MEMCACHED_PORT),
    connect_timeout=5,
    serializer=json_serializer,
    deserializer=json_deserializer
)
