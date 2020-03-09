import pytest
import BlockchainDB
import os
import signal


@pytest.fixture
def client():
    BlockchainDB.app.config['TESTING'] = True

    with BlockchainDB.app.test_client() as client:
        with BlockchainDB.app.app_context():
            BlockchainDB.for_tests()
        yield client


# TODO: kill the chain
#    pid = os.getpid()
#    sig = signal.SIGSTOP
#    os.kill(pid, sig)


def test_get_chain(client):
    chain = client.get('/get_chain')
    assert b'{"chain":[{"database_key":0,"document":[],"index":1,"previous_hash":"0","proof":1' in chain.data


def test_create_document(client):
    chain = client.post('/create_document', json={
        'database_key': '12345678',
        'document': 'test document',
        'encrypt': 'True'})

    assert b'New key for document' in chain.data


def test_create_multiple_documents(client):
    chain = client.post('/create_documents', json={
        'database_key': '12345678',
        'documents': {
            'document1': 'test document 1',
            'document2': 'test document 2',
            'document3': 'test document 3',
            'document4': 'test document 4',
            'document5': 'test document 5',
        },
        'encrypt': 'True'})

    assert b'New key for document' in chain.data

