from datetime import timedelta, datetime, date
import pytest
from oauthlib.common import Request

from benwaonline_auth.cache import cache
from benwaonline_auth.bwoauth.core import BenwaValidator
from benwaonline_auth.models import Client, User, Token

validator = BenwaValidator()

def auth_client():
    return Client(
        name='test',
        client_id='test_id',
        client_secret='test_secret',
        is_confidential=True,
        blacklisted=False,
        grant_type='authorization_code',
        response_type='code',
        _redirect_uris='http://test/callback',
        allowed_scopes='ham test thanks',
        default_scopes='ham test'
    )

def auth_user():
    return User(user_id='6969')

def auth_token():
    return Token(
        code='testtoken',
        created_on=datetime(2016, 11, 1),
        expires_in=timedelta(days=14),
        user_id='6969',
        client_id='test_id',
        scopes='ham test'
    )

def request_generated_token():
    return {
        'access_token': 'genereated_token_value',
        'expires_in': 3600,
        'token_type': 'Bearer',
        'refresh_token': 'refreshing'
    }

def cache_entry():
    return {
        'scopes': 'test scopes',
        'redirect_uri': 'http://test/callback',
        'client_id': 'test_id',
        'state': 'test_state',
        'user': 'test_user',
        'client': auth_client()
    }

def _mock_model(mocker, model):
    return mocker.patch('benwaonline_auth.bwoauth.core.' + model)

def mock_client_get_query(mocker, client):
    mock = _mock_model(mocker, 'Client')
    mock.query.get.return_value = client
    return mock

def mock_user_get_query(mocker, user):
    mock = _mock_model(mocker, 'User')
    mock.query.get.return_value = user
    return mock

def mock_token_get_query(mocker, token):
    mock = _mock_model(mocker, 'Token')
    mock.query.get.return_value = token
    return mock

def mock_cache_entry(mocker, cache_entry):
    mocked_cache = mocker.patch('benwaonline_auth.bwoauth.core.cache')
    mocked_cache.get.return_value = cache_entry

@pytest.fixture(scope='function')
def request_(session):
    _request = Request('does it matter')
    yield _request

def test_validate_client_id_valid(request_, mocker):
    test_client = auth_client()

    mock_client_get_query(mocker, test_client)

    assert validator.validate_client_id('test_id', request_)
    assert request_.client.name == auth_client().name

def test_validate_client_id_invalid(request_, mocker):
    mock_client_get_query(mocker, None)

    assert validator.validate_client_id('test_id', request_) == False

def test_validate_client_id_blacklisted_client(request_, mocker):
    test_client = auth_client()
    test_client.blacklisted = True

    mock_client_get_query(mocker, test_client)

    assert validator.validate_client_id('test_id', request_) == False

@pytest.mark.parametrize('redirect_uri, valid', [
        ('http://test/callback', True),
        ('http://test/invalid', False)
    ])
def test_validate_redirect_uri_valid(request_, redirect_uri, valid):
    test_client = auth_client()
    request_.client = test_client

    assert validator.validate_redirect_uri('test_id', redirect_uri, request_) == valid

def test_get_default_redirect_uri():
    test_client = auth_client()
    request_.client = test_client

    assert validator.get_default_redirect_uri('doesnt_matter', Request('idc')) == None

def test_validate_scopes(request_):
    test_client = auth_client()
    request_.client = test_client

    scopes = ['slam', 'ham', 'thanks']
    validator.validate_scopes(test_client.client_id, scopes, test_client, request_)

    assert 'ham' in request_.scopes
    assert 'thanks' in request_.scopes
    assert 'slam' not in request_.scopes

def test_get_default_scopes(request_):
    test_client = auth_client()
    request_.client = test_client

    assert auth_client().default_scopes == validator.get_default_scopes(test_client.client_id, request_)

@pytest.mark.parametrize('response_type, valid', [
        ('code', True),
        ('not_code', False)
    ])
def test_validate_response_type(request_, response_type, valid):
    test_client = auth_client()
    request_.client = test_client

    assert validator.validate_response_type(test_client.client_id, response_type, test_client, request_) == valid

def test_save_authorization_code():
    request = Request('does it matter', body=cache_entry())
    validator.save_authorization_code(request.client.client_id, {'code': 'code'}, request)

    assert cache.get('code')

@pytest.mark.parametrize('param', [
        ('client_id', None),
        ('client_id', 'not_in_the_db')
    ])
def test_authenticate_client_invalid_request(request_, param):
    setattr(request_, *param)

    assert validator.authenticate_client(request_) == False

@pytest.mark.parametrize('param, client_secret, authenticated', [
        (('blacklisted', True), None, False),
        (('is_confidential', False), 'incorrect', False),
        (('blacklisted', False), 'incorrect', False),
        (('blacklisted', False), auth_client().client_secret, True)
    ])
def test_authenticate_client(request_, mocker, param, client_secret, authenticated):
    test_client = auth_client()
    setattr(test_client, *param)

    mock_client_get_query(mocker, test_client)

    request_.client_id = test_client.client_id
    request_.client_secret = client_secret

    assert validator.authenticate_client(request_) == authenticated

def test_authenticate_client_id(request_):
    request_.client_id = 'test_id'

    assert validator.authenticate_client_id(request_.client_id, request_) == False

@pytest.mark.parametrize('cache_entry, client_id, validated', [
        (None, 'its wrong', False),
        (cache_entry(), 'its wrong', False),
        (cache_entry(), auth_client().client_id, True)
    ])
def test_validate_code_cache(request_, mocker, cache_entry, client_id, validated):
    test_client = auth_client()

    mock_cache_entry(mocker, cache_entry)

    assert validator.validate_code(client_id, 'a_code', test_client, request_) == validated

@pytest.mark.parametrize("cache_entry, redirect_uri", [
        (cache_entry(), 'obviously_wrong'),
        (None, cache_entry()['redirect_uri']),
        (cache_entry(), cache_entry()['redirect_uri'])
    ])
def test_confirm_redirect_uri(mocker, cache_entry, redirect_uri):
    test_client = auth_client()

    mock_cache_entry(mocker, cache_entry)

    assert validator.confirm_redirect_uri(test_client.client_id, 'a_code', test_client, redirect_uri) == False

@pytest.mark.parametrize("grant_type, supported", [
        (auth_client().grant_type, True),
        ('refresh_token', True),
        ('invalid', False)
    ])
def test_validate_grant_type(request_, grant_type, supported):
    test_client = auth_client()
    request_.client = test_client

    assert validator.validate_grant_type(test_client.client_id, grant_type, test_client, request_) == supported

def token_side_effect(arg):
    return arg

@pytest.mark.parametrize("param, expired", [
        (('refresh_token', None), False),
        (('refresh_token', auth_token()), True),
        (('refresh_token', auth_token()), False)
    ])
def test_save_bearer_token(request_, mocker, param, expired):
    test_user = auth_user()
    setattr(test_user, *param)
    test_client = auth_client()

    request_.user = {'user_id': test_user.user_id}
    request_.client = test_client
    token = request_generated_token()

    mock_user_get_query(mocker, test_user)
    mocker.patch('benwaonline_auth.bwoauth.core.BenwaValidator.save_refresh_token')
    mocker.patch('benwaonline_auth.bwoauth.core.check_expiration', return_value=expired)

    result = validator.save_bearer_token(token, request_)
    assert result == test_client.default_redirect_uri

def test_save_bearer_token_no_user_found(request_, mocker):
    test_user = auth_user()
    test_client = auth_client()
    request_.user = {'user_id': test_user.user_id}
    request_.client = test_client
    token = request_generated_token()

    mock_user_get_query(mocker, None)

    result = validator.save_bearer_token(token, request_)
    assert result == test_client.default_redirect_uri

def test_get_original_scopes(request_, mocker):
    test_token = auth_token()
    mock_token_get_query(mocker, test_token)

    assert validator.get_original_scopes(test_token, request_) == test_token.scopes

def patch_utcnow(mocker, now):
    mock_date = mocker.patch('benwaonline_auth.bwoauth.core.datetime')
    mock_date.utcnow.return_value = now
    mock_date.side_effect = lambda *args, **kw: date(*args, **kw)

@pytest.mark.parametrize("now, expired", [
        (datetime(2016, 12, 1), True),
        (datetime(2016, 10, 1), False)
    ])
def test_rotate_refresh_token_expired(request_, mocker, now, expired):
    test_token = auth_token()
    test_token.expires_in = timedelta(microseconds=1)

    mock_token_get_query(mocker, test_token)
    patch_utcnow(mocker, now)

    assert validator.rotate_refresh_token(request_) == expired

@pytest.mark.parametrize('client_id, token, validated', [
    ('test_id', None, False),
    ('wrong', auth_token(), False),
    ('test_id', auth_token(), True),
])
def test_validate_refresh_token(request_, mocker, client_id, token, validated):
    test_client = auth_client()
    test_client.client_id = client_id

    mock_token_get_query(mocker, token)
    mock_user_get_query(mocker, auth_user())

    assert validator.validate_refresh_token(None, test_client, request_) == validated

def test_validate_refresh_token_no_refresh_token(request_, mocker):
    test_client = auth_client()
    refresh_token = None

    assert validator.validate_refresh_token(refresh_token, test_client, request_) == False
