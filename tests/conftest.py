from datetime import timedelta
import pytest

from benwaonline_auth import create_app
from benwaonline_auth.database import db as _db
from benwaonline_auth import models

@pytest.fixture(scope='session')
def testdir(tmpdir_factory):
    fn = tmpdir_factory.mktemp('test')
    yield fn

@pytest.fixture(scope='session')
def app(testdir):
    app = create_app('test')

    with app.app_context():
        yield app

@pytest.fixture(scope='session')
def db(app):
    _db.app = app
    _db.drop_all()
    _db.create_all()

    init_clients(_db.session)
    init_users(_db.session)
    init_tokens(_db.session)

    yield _db

    _db.drop_all()

@pytest.fixture(scope='function')
def session(db):
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)

    db.session = session
    yield session

    transaction.rollback()
    connection.close()
    session.remove()

def init_clients(session):
    client = models.Client(
        name='test',
        client_id='test_id',
        client_secret='test_secret',
        is_confidential=True,
        blacklisted=False,
        response_type='code',
        _redirect_uris='http://test/callback',
        default_scopes='ham test'
    )
    session.add(client)
    session.commit()

    return

def init_tokens(session):
    token = models.Token(
        code='testtoken',
        expires_in=timedelta(days=14),
        user_id='6969',
        client_id='test_id',
        scopes='ham test'
    )

    expired = models.Token(
        code='expired',
        expires_in=timedelta(microseconds=1),
        is_expired=True,
        user_id='420',
        client_id='test_id',
        scopes='ham test'
    )

    session.add(token)
    session.add(expired)
    session.commit()

    return

def init_users(session):
    user = models.User(
        user_id='6969'
    )
    session.add(user)

    user = models.User(
        user_id='420'
    )
    session.add(user)
    session.commit()

    return
