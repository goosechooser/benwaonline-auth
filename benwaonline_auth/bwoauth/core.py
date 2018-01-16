'''This module handles the validation (and responding to) authentication requests'''
import os
from datetime import datetime, timedelta
from jose import jwt
from flask import logging, current_app
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.common import generate_token

from benwaonline_auth.database import db
from benwaonline_auth.models import Client, Token, User
from benwaonline_auth.schemas import UserSchema
from benwaonline_auth.bwoauth import cache
from benwaonline_auth.config import app_config

CFG = app_config[os.getenv('FLASK_CONFIG')]

def generate_jwt_token(request):
    ''' Generates a JWT'''
    now = (datetime.utcnow() - datetime(1970, 1, 1))
    exp_at = now + timedelta(seconds=3600)

    claims = {
        'iss': CFG.ISSUER,
        'aud': CFG.API_AUDIENCE,
        'sub': request.user['user_id'],
        'iat': now.total_seconds(),
        'exp': exp_at.total_seconds()
    }
    headers = {
        'typ': 'JWT',
        'alg': 'RS256',
        'kid': 'benwaonline'
    }
    return jwt.encode(claims, CFG.PRIVATE_KEY, algorithm='RS256', headers=headers)

def generate_refresh_token(request):
    '''Generates a refresh token.

    Returns:
        a randomly generated string of 30 characters.
    '''
    return generate_token()

class BenwaValidator(RequestValidator):
    '''Validates requests of the Authorization Grant flow'''
    def validate_client_id(self, client_id, request, *args, **kwargs):
        '''Simple validity check, does client exist? Not banned?

        Returns:
            True if client_id is valid, False otherwise
        '''
        client = Client.query.get(client_id)
        if not client or client.blacklisted:
            current_app.logger.info('Unauthorized client request attempt')
            return False

        request.client = client
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        '''Is the client allowed to use the supplied redirect_uri?
        i.e. has the client previously registered this EXACT redirect uri.

        Returns:
            True if the redirect_uri in the request is allowed, False otherwise
        '''
        return False if redirect_uri not in request.client.redirect_uris else True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        '''The redirect used if none has been supplied.

        We require clients to pre register any redirect uris.
        '''
        return None

    # Do this better
    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        '''Check if requested scopes are in the client's allowed scopes.

        Set the scopes in the request object.

        Returns:
            True
        '''
        request.scopes = request.client.default_scopes
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        '''Scopes a client will authorize for if none are supplied in the authorization request.

        This is fed to the function 'utils.scope_to_list' so we don't need to split it.
        Returns:
            a string representing the scopes, space seperated.
        '''
        return request.client.default_scopes

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        '''Check that the given response type is allowed by the client and/or the endpoint.

        Returns:
            True if the response type is allowed by the client, False otherwise.
        '''
        return response_type == request.client.response_type


    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        '''Saves the authorization code and any other pertinent attributes.'''
        associations = {
            'scopes': request.scopes,
            'redirect_uri': request.redirect_uri,
            'client_id': client_id,
            'state': request.state,
            'user': request.user
        }
        cache.set(code['code'], associations, timeout=5*60)
        return

    # Token request

    def authenticate_client(self, request, *args, **kwargs):
        '''Authenticate the client.

        We store the object representing the client in the request.

        Returns:
            True if the client was authenticated, False otherwise
        '''

        # Request didn't include 'client_id'
        try:
            client = Client.query.get(request.client_id)
        except TypeError as err:
            current_app.logger.error('Request did not include a client_id', request, err)
            return False

        # Didn't find client in db
        if not client:
            return False

        is_allowed = True if not client.blacklisted and client.is_confidential else False
        if is_allowed and request.client_secret == client.client_secret:
            request.client = client
            return True

        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        '''Don't allow public (non-authenticated) clients

        This method is unused'''
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        '''Validate the code belongs to the client.

        Add associated scopes, state and user to request.scopes and request.user

        Returns:
            True if the code belongs to the client, False otherwise
        '''

        cached = cache.get(code)
        if cached['client_id'] != client_id:
            return False

        request.scopes = cached['scopes']
        request.user = cached['user']
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        # When we generate our authorization code we must save the redirect_uri
        # here we check
        cached = cache.get(code)
        return redirect_uri == cached['redirect_uri']

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        if request.body['grant_type'] not in ['authorization_code', 'refresh_token']:
            return False

        return True

    # What we're saving is really the refresh token
    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token.
        (Save the refresh token)

        The refresh token is associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time

        The token dict may hold a number of items:
            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client
            }

        :param client_id: Unicode client identifier
        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client
        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
        """

        user = User.query.get(request.user['user_id'])
        if not user.refresh_token or user.refresh_token.is_expired:
            current_app.logger.info('Creating new refresh token for user', user.user_id)
            refresh_token = Token(
                code=token['refresh_token'],
                expires_in=CFG.REFRESH_TOKEN_LIFESPAN,
                scopes=' '.join(request.scopes)
            )

            # Consider keeping a seperate model for RevokedTokens?
            db.session.add(refresh_token)
            client = Client.query.get(request.client.client_id)
            client.refresh_tokens.append(refresh_token)
            user.refresh_token = refresh_token
            db.session.commit()

        return

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        return cache.delete(code)

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        token = Token.query.get(refresh_token)
        return token.scopes

    def rotate_refresh_token(self, request):
        """Determine whether to rotate the refresh token. Default, yes.
        When access tokens are refreshed the old refresh token can be kept
        or replaced with a new one (rotated). Return True to rotate and
        and False for keeping original.
        :param request: oauthlib.common.Request
        :rtype: True or False
        Method is used by:
            - Refresh Token Grant
        """
        token = Token.query.get(request.refresh_token)
        token.is_expired = token.created_on < datetime.utcnow() - token.expires_in
        return token.is_expired

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.
        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.
        :param refresh_token: Unicode refresh token
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False
        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """
        try:
            token = Token.query.get(refresh_token)
        except TypeError:
            return False

        if not token:
            current_app.logger.debug('Token not found')
            return False

        if token.client_id != client.client_id:
            current_app.logger.debug('Client_id in token does not match the client\'s registered id')
            return False

        user = User.query.get(token.user_id)
        request.user = UserSchema().dump(user).data

        return True
