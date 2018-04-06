from sqlalchemy_utils import ChoiceType
from benwaonline_auth.database import db

GRANT_TYPES = [
        ('authorization_code', 'Authorization code'),
        ('refresh_token', 'Refresh token')
    ]

RESPONSE_TYPES = [
    ('code', 'Authorization code')
]

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.String(20), primary_key=True)
    refresh_token = db.relationship('Token', uselist=False, backref='user')
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    # Todo: Users and Clients are a many-to-many
    # clients =

class Token(db.Model):
    __tablename__ = 'token'
    code = db.Column(db.String(40), primary_key=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    expires_in = db.Column(db.Interval)
    is_expired = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.String(20), db.ForeignKey('user.user_id'))
    client_id = db.Column(db.String(40), db.ForeignKey('client.client_id'))
    scopes = db.Column(db.Text)

class Client(db.Model):
    __tablename__ = 'client'
    name = db.Column(db.String(40))
    created_on = db.Column(db.DateTime, server_default=db.func.now())

    client_id = db.Column(db.String(40), primary_key=True)
    # Need to generate and hash this
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)

    # public or confidential
    is_confidential = db.Column(db.Boolean, default=True)
    blacklisted = db.Column(db.Boolean, default=False)
    grant_type = db.Column(ChoiceType(GRANT_TYPES))
    response_type = db.Column(ChoiceType(RESPONSE_TYPES))

    _redirect_uris = db.Column(db.Text)
    allowed_scopes = db.Column(db.Text)
    default_scopes = db.Column(db.Text)

    refresh_tokens = db.relationship('Token', backref='client', lazy='dynamic')

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]
