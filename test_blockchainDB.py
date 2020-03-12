import pytest
import json
from BlockchainDB import app
import uuid

# TODO: Test errors!


def test_get_chain():
    chain = app.test_client().get('/get_chain')
    assert b'{"chain":[{"database key":0,"document":{},"index":1,"previous_hash":"0","proof":1' in chain.data


def test_create_document():
    database_key = str(uuid.uuid4())
    chain = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': 'test_create_document test document',
        'encrypt': 'True'})

    assert b'Document successfully created' in chain.data


def test_create_multiple_documents():
    database_key = str(uuid.uuid4())
    chain = app.test_client().post('/create_documents', json={
        'database key': database_key,
        'documents': {
            'document1': 'test_create_multiple_documents test document 1',
            'document2': 'test_create_multiple_documents test document 2',
            'document3': 'test_create_multiple_documents test document 3',
            'document4': 'test_create_multiple_documents test document 4',
            'document5': 'test_create_multiple_documents test document 5',
        },
        'encrypt': 'True'})

    assert b'Documents successfully created' in chain.data


# TODO: check whether the reverse loop works with an update to the document
def test_get_latest():
    database_key = str(uuid.uuid4())
    doc_keys = app.test_client().post('/create_documents', json={
        'database key': database_key,
        'documents': {
            'document1': 'test_get_latest test document 1',
            'document2': 'test_get_latest test document 2',
            'document3': 'test_get_latest test document 3',
            'document4': 'test_get_latest test document 4',
            'document5': 'test_get_latest test document 5',
        },
        'encrypt': 'True'})

    json_file = json.loads(doc_keys.data)
    doc1_key = json_file['document keys']['document1']['document key']

    chain = app.test_client().post('/get_latest', json={
        'database key': database_key,
        'document key': doc1_key
    })

    assert b'Document successfully retrieved' in chain.data


def test_get_version():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_documents', json={
        'database key': database_key,
        'documents': {
            'document1': 'test_get_version test document 1',
            'document2': 'test_get_version test document 2',
            'document3': 'test_get_version test document 3',
            'document4': 'test_get_version test document 4',
            'document5': 'test_get_version test document 5',
        },
        'encrypt': 'True'})

    json_file = json.loads(doc_creation.data)
    doc1_key = json_file['document keys']['document1']['document key']

    chain = app.test_client().post('/get_version', json={
        'database key': database_key,
        'document key': doc1_key,
        'version': 0
    })

    assert b'Document version 0 successfully retrieved' in chain.data


# TODO: check if it does get all versions after an update
def test_get_all_versions():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_documents', json={
        'database key': database_key,
        'documents': {
            'document1': 'test_get_versions test document 1',
            'document2': 'test_get_versions test document 2',
            'document3': 'test_get_versions test document 3',
            'document4': 'test_get_versions test document 4',
            'document5': 'test_get_versions test document 5',
        },
        'encrypt': 'True'})

    json_file = json.loads(doc_creation.data)
    doc1_key = json_file['document keys']['document1']['document key']

    chain = app.test_client().post('/get_all_versions', json={
        'database key': database_key,
        'document key': doc1_key
    })

    assert b'All document versions successfully retrieved' in chain.data
