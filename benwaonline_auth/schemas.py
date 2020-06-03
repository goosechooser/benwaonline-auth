from marshmallow import Schema, fields, post_load
from benwaonline_auth.models import User, Token, Client

class UserSchema(Schema):
    user_id = fields.Str()
    refresh_token = fields.Nested('TokenSchema', exclude=('user',))
    created_on = fields.DateTime()

    @post_load
    def make_user(self, data, **kwargs):
        return User(**data)

class TokenSchema(Schema):
    code = fields.Str()
    created_on = fields.DateTime()
    expires_in = fields.TimeDelta()
    expires_on = fields.DateTime()
    user = fields.Nested('UserSchema', exclude=('refresh_token',))
    scopes = fields.Str()

    @post_load
    def make_token(self, data, **kwargs):
        return Token(**data)

class ClientSchema(Schema):
    name = fields.Str()
    client_id = fields.Str()
    client_secret = fields.Str()
    is_confidential = fields.Bool()
    blacklisted = fields.Bool()
    response_type = fields.Str()
    redirect_uris = fields.Str(attribute='_redirect_uris')
    default_scopes = fields.Str(attribute='_default_scopes')
    refresh_tokens = fields.List(fields.Nested('TokenSchema'))

    @post_load
    def make_client(self, data, **kwargs):
        return Client(**data)