import json
from marshmallow import pprint
from Cryptodome.PublicKey import RSA
from jose import jwk, jwt

def make_private(key, fname):
    pv_key_string = key.exportKey()
    str_key = "{}".format(pv_key_string.decode())
    with open (fname + '_priv.pem', "w") as prv_file:
        print(str_key, file=prv_file)
    return str_key

def make_public(key, fname):
    pb_key_string = key.publickey().exportKey()
    str_key = "{}".format(pb_key_string.decode())
    with open (fname + '_pub.pem', "w") as pub_file:
        print(str_key, file=pub_file)
    return str_key

# ISSUER, AUDIENCE, and kid will all be grabbed from the app.config/.env file, etc
def make_token(key):
    return jwt.encode({'iss': 'test', 'aud': 'yea', 'henlo': 'stupid'}, key, algorithm='RS256', headers={'kid': 'benwaonline'})

def make_jwk(key, kid):
    jwks = jwk.construct(key, 'RS256').to_dict()
    pprint(jwks)
    jwks['e'] = jwks['e'].decode('utf-8')
    jwks['n'] = jwks['n'].decode('utf-8')
    jwks['use'] = 'sig'
    jwks['kid'] = kid
    return {'keys':[jwks]}

'''
Take aways
* generate pub and private keys (.pem) before auth server is up
* load these into auth server
* use private key to generate tokens
* use public key to create 'jwks.json' which api server can use to verify
'''

if __name__ == '__main__':
    key = RSA.generate(2048)

    priv = make_private(key, 'benwaauth')
    pub = make_public(key, 'benwaauth')
    token = make_token(priv)
    jwks = make_jwk(pub, 'benwaonline')

    with open('jwks.json', 'w') as f:
        json.dump(jwks, f)

