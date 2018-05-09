'''This module handles the validation (and responding to) authentication requests'''
import os
from datetime import datetime, timedelta
from jose import jwt
from flask import logging, current_app
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.utils import list_to_scope, scope_to_list
from oauthlib.common import generate_token

from benwaonline_auth.database import db
from benwaonline_auth.models import Client, Token, User
from benwaonline_auth.schemas import UserSchema
from benwaonline_auth.cache import cache
from benwaonline_auth.config import app_config

CFG = app_config[os.getenv('FLASK_CONFIG')]

def generate_jwt_token(request):
    ''' Generates a JWT'''
    now = datetime.utcnow() - datetime(1970,1,1)
    exp_at = now + timedelta(seconds=3600)
    claims = {
        'iss': CFG.ISSUER,
        'aud': CFG.API_AUDIENCE,
        'sub': request.user['user_id'],
        'scopes': request.scopes,
        'iat': int(now.total_seconds()),
        'exp': int(exp_at.total_seconds())
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

def check_expiration(token):
    '''Checks if token is expired or not.

    Returns:
        True if token is expired, False if not/
    '''
    now = datetime.utcnow()
    expires_on = token.created_on + token.expires_in

    return expires_on < now

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
        msg = 'Supplied uri: {}\nUri stored in request: {}'.format(redirect_uri, request.client.redirect_uris)
        current_app.logger.debug(msg)
        return False if redirect_uri not in request.client.redirect_uris else True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        '''The redirect used if none has been supplied.

        We require clients to pre register any redirect uris.
        '''
        return None

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        '''Check if requested scopes are in the client's allowed scopes.

        Set the normalized set of scopes in the request object.

        Returns:
            True
        '''
        req_scopes = [scope for scope in scopes if scope in client.allowed_scopes]
        request.scopes = list_to_scope(req_scopes)

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
        msg = 'Scopes in the request: {}'.format(request.scopes)
        current_app.logger.debug(msg)
        associations = {
            'scopes': request.scopes,
            'redirect_uri': request.redirect_uri,
            'client_id': client_id,
            'state': request.state,
            'user': request.user
        }

        cache.set(code['code'], associations, timeout=10*60)

        return

    # Token request

    def authenticate_client(self, request, *args, **kwargs):
        '''Authenticate the client.

        We store the object representing the client in the request.

        Returns:
            True if the client was authenticated, False otherwise
        '''

        try:
            client = Client.query.get(request.client_id)
        except TypeError as err:
            msg = 'Request did not include a id {} {}'.format(request, err)
            current_app.logger.debug(msg)
            return False

        if not client:
            msg = 'Did not find Client with supplied id {}'.format(request.client_id)
            current_app.logger.debug(msg)
            return False

        if client.blacklisted:
            msg = 'Supplied Client with id {} is blacklisted'.format(request.client_id)
            current_app.logger.debug(msg)
            return False

        if not client.is_confidential:
            msg = 'Supplied Client with id {} is not a confidential client'.format(request.client_id)
            current_app.logger.debug(msg)
            return False

        if request.client_secret == client.client_secret:
            request.client = client
            return True

        msg = 'Supplied client secret is incorrect'
        current_app.logger.debug(msg)
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

        if cached is None:
            msg = 'validate_code - Code {} not found, possibly invalidated'.format(code)
            current_app.logger.info(msg)
            return False

        if cached.get('client_id', None) != client_id:
            msg = 'validate_code - Client id in cache does not make supplied client id'
            current_app.logger.info(msg)
            return False

        request.scopes = cached['scopes']
        msg = 'Scopes in the request: {}'.format(request.scopes)
        current_app.logger.debug(msg)
        request.user = cached['user']
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        # When we generate our authorization code we must save the redirect_uri
        # here we check
        cached = cache.get(code)

        if cached is None:
            msg = 'confirm_redirect_uri - Code {} not found, possibly invalidated'.format(code)
            current_app.logger.info(msg)
            return False

        return redirect_uri == cached['redirect_uri']

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        return grant_type in [request.client.grant_type, 'refresh_token']

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

        if not user:
            msg = 'User {} not found'.format(request.user['user_id'])
            current_app.logger.debug(msg)
            return request.client.default_redirect_uri

        try:
            user.refresh_token.is_expired = check_expiration(user.refresh_token)
        except AttributeError:
            msg = 'User does not have a refresh token\nCreating new refresh token for user {}'.format(user.user_id)
            current_app.logger.info(msg)
            self.save_refresh_token(token, request, user)
        else:
            if user.refresh_token.is_expired:
                msg = 'Refresh token for user is expired\nCreating new refresh token for user {}'.format(user.user_id)
                current_app.logger.info(msg)
                self.save_refresh_token(token, request, user)

        return request.client.default_redirect_uri

    def save_refresh_token(self, token, request, user):
        refresh_token = Token(
            code=token['refresh_token'],
            expires_in=CFG.REFRESH_TOKEN_LIFESPAN,
            scopes=list_to_scope(request.scopes)
        )

        db.session.add(refresh_token)
        request.client.refresh_tokens.append(refresh_token)
        user.refresh_token = refresh_token
        db.session.commit()

        msg = 'Added new refresh token to client {} and user {}'.format(request.client.client_id, user.user_id)
        current_app.logger.debug(msg)

        return

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        msg = 'Deleting code {} from the cache'.format(code)
        current_app.logger.debug(msg)

        return cache.delete(code)

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        token = Token.query.get(refresh_token)
        msg = 'Scopes in the token: {}'.format(token.scopes)
        current_app.logger.debug(msg)
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
        token.is_expired = check_expiration(token)

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
            msg = 'No refresh token supplied'
            current_app.logger.debug(msg)
            return False

        if not token:
            msg = 'Refresh token with code {} not found'.format(refresh_token)
            current_app.logger.debug(msg)
            return False

        if token.client_id != client.client_id:
            current_app.logger.debug('Client_id in token does not match the client\'s registered id')
            return False

        user = User.query.get(token.user_id)
        request.user = UserSchema().dump(user).data

        return True
