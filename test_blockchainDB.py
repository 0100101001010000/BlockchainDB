import pytest
import json
import base64

from werkzeug.datastructures import FileStorage

from BlockchainDB import app
import uuid
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# TODO: Test errors!


def test_get_chain():
    chain = app.test_client().get('/get_chain')
    assert b'{"chain":[{"database key":0,"document":{},"index":1,"previous_hash":"0","proof":1' in chain.data


def test_create_document():
    database_key = str(uuid.uuid4())
    chain = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': 'test_create_document test document',
        'encrypt': 'True'
    })

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
        'encrypt': 'True'
    })

    assert b'Documents successfully created' in chain.data


# TODO: check whether the reverse loop works with an update to the document
def test_get_latest():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_documents', json={
        'database key': database_key,
        'documents': {
            'document1': 'test_get_latest test document 1',
            'document2': 'test_get_latest test document 2',
            'document3': 'test_get_latest test document 3',
            'document4': 'test_get_latest test document 4',
            'document5': 'test_get_latest test document 5',
        },
        'encrypt': 'True'
    })

    assert b'Documents successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
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
        'encrypt': 'True'
    })

    assert b'Documents successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc1_key = json_file['document keys']['document1']['document key']

    chain = app.test_client().post('/get_version', json={
        'database key': database_key,
        'document key': doc1_key,
        'version': 0
    })

    assert b'Document version 0 successfully retrieved' in chain.data

    doc_update = app.test_client().post('/update_document', json={
        'database key': database_key,
        'document key': doc1_key,
        'document': 'test_update_document test document update',
        'encrypt': 'True'
    })

    assert b'Document successfully updated' in doc_update.data

    updated_chain = app.test_client().post('/get_version', json={
        'database key': database_key,
        'document key': doc1_key,
        'version': 1
    })

    assert b'Document version 1 successfully retrieved' in updated_chain.data


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
        'encrypt': 'True'
    })

    assert b'Documents successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc1_key = json_file['document keys']['document1']['document key']

    chain = app.test_client().post('/get_all_versions', json={
        'database key': database_key,
        'document key': doc1_key
    })

    assert b'All document versions successfully retrieved' in chain.data

    doc_update = app.test_client().post('/update_document', json={
        'database key': database_key,
        'document key': doc1_key,
        'document': 'test_update_document test document update',
        'encrypt': 'True'
    })

    assert b'Document successfully updated' in doc_update.data

    chain_update = app.test_client().post('/get_all_versions', json={
        'database key': database_key,
        'document key': doc1_key
    })

    assert b'All document versions successfully retrieved' in chain_update.data


def test_get_all_db_documents():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_documents', json={
        'database key': database_key,
        'documents': {
            'document1': 'test_get_all_db_documents test document 1',
            'document2': 'test_get_all_db_documents test document 2',
            'document3': 'test_get_all_db_documents test document 3',
            'document4': 'test_get_all_db_documents test document 4',
            'document5': 'test_get_all_db_documents test document 5',
        },
        'encrypt': 'True'
    })

    assert b'Documents successfully created' in doc_creation.data

    chain = app.test_client().post('/get_all_db_documents', json={
        'database key': database_key
    })

    assert b'All documents successfully retrieved' in chain.data


def test_update_document():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': 'test_update_document test document',
        'encrypt': 'True'
    })

    assert b'Document successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc_key = json_file['document key']

    chain = app.test_client().post('/update_document', json={
        'database key': database_key,
        'document key': doc_key,
        'document': 'test_update_document test document update',
        'encrypt': 'True'
    })

    assert b'Document successfully updated' in chain.data


def test_delete_document():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': 'test_delete_document test document',
        'encrypt': 'True'
    })

    assert b'Document successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc_key = json_file['document key']

    chain = app.test_client().post('/delete_document', json={
        'database key': database_key,
        'document key': doc_key,
        'encrypt': 'True'
    })

    assert b'Document successfully deleted' in chain.data


def test_resurrect_document():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': 'test_resurrect_document test document',
        'encrypt': 'True'
    })

    assert b'Document successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc_key = json_file['document key']

    doc_deletion = app.test_client().post('/delete_document', json={
        'database key': database_key,
        'document key': doc_key,
        'encrypt': 'True'
    })

    assert b'Document successfully deleted' in doc_deletion.data

    chain = app.test_client().post('/resurrect_document', json={
        'database key': database_key,
        'document key': doc_key,
        'encrypt': 'True'
    })


def test_restore_document():
    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': 'test_restore_document test document',
        'encrypt': 'True'
    })

    assert b'Document successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc_key = json_file['document key']

    doc_update = app.test_client().post('/update_document', json={
        'database key': database_key,
        'document key': doc_key,
        'document': 'test_update_document test document update',
        'encrypt': 'True'
    })

    assert b'Document successfully updated' in doc_update.data

    chain = app.test_client().post('/restore_document', json={
        'database key': database_key,
        'document key': doc_key,
        'version': 0
    })

    assert b'Document successfully restored' in chain.data


def test_string_encryption():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("test_string_encryption_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("test_string_encryption_receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    document = "test_encryption test document".encode("utf-8")

    recipient_key = RSA.import_key(open("test_string_encryption_receiver.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)

    encrypted_string = enc_session_key
    encrypted_string += cipher_aes.nonce
    encrypted_string += tag
    encrypted_string += ciphertext

    private_key_retrieved = RSA.import_key(open("test_string_encryption_private.pem").read())

    position = private_key_retrieved.size_in_bytes()
    enc_session_key_retrieved = encrypted_string[:position]
    nonce_retrieved = encrypted_string[position:position+16]
    position += 16
    tag_retrieved = encrypted_string[position:position+16]
    position += 16
    ciphertext_retrieved = encrypted_string[position:]

    assert enc_session_key_retrieved == enc_session_key
    assert nonce_retrieved == cipher_aes.nonce
    assert tag_retrieved == tag
    assert ciphertext_retrieved == ciphertext

    cipher_rsa_retrieved = PKCS1_OAEP.new(private_key_retrieved)

    session_key = cipher_rsa_retrieved.decrypt(enc_session_key_retrieved)

    cipher_aes_retrieved = AES.new(session_key, AES.MODE_EAX, nonce_retrieved)
    data = cipher_aes_retrieved.decrypt_and_verify(ciphertext_retrieved, tag_retrieved)
    assert data.decode('utf-8') == document.decode('utf-8')


# TODO: Test with document encryption encrypt the document and see if it all still works
def test_encrypted_document_upload():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("test_encrypted_document_upload_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("test_encrypted_document_upload_receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    document = "test_encrypted_document_upload test document".encode("utf-8")

    recipient_key = RSA.import_key(open("test_encrypted_document_upload_receiver.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)
    encrypted_string = enc_session_key
    encrypted_string += cipher_aes.nonce
    encrypted_string += tag
    encrypted_string += ciphertext

    b64encoded_string = base64.b64encode(encrypted_string).decode("utf-8")

    database_key = str(uuid.uuid4())
    doc_creation = app.test_client().post('/create_document', json={
        'database key': database_key,
        'document': b64encoded_string,
        'encrypt': 'True'
    })

    assert b'Document successfully created' in doc_creation.data

    json_file = json.loads(doc_creation.data)
    doc_key = json_file['document key']

    chain = app.test_client().post('/get_latest', json={
        'database key': database_key,
        'document key': doc_key
    })

    assert b'Document successfully retrieved' in chain.data

    json_file2 = json.loads(chain.data)
    encrypted_document = json_file2['document']['document']
    b64decoded_string = base64.b64decode(encrypted_document)

    private_key_retrieved = RSA.import_key(open("test_encrypted_document_upload_private.pem").read())

    position = private_key_retrieved.size_in_bytes()
    enc_session_key_retrieved = b64decoded_string[:position]
    nonce_retrieved = b64decoded_string[position:position+16]
    position += 16
    tag_retrieved = b64decoded_string[position:position+16]
    position += 16
    ciphertext_retrieved = b64decoded_string[position:]

    assert enc_session_key_retrieved == enc_session_key
    assert nonce_retrieved == cipher_aes.nonce
    assert tag_retrieved == tag
    assert ciphertext_retrieved == ciphertext

    cipher_rsa_retrieved = PKCS1_OAEP.new(private_key_retrieved)
    session_key = cipher_rsa_retrieved.decrypt(enc_session_key_retrieved)

    cipher_aes_retrieved = AES.new(session_key, AES.MODE_EAX, nonce_retrieved)
    data = cipher_aes_retrieved.decrypt_and_verify(ciphertext_retrieved, tag_retrieved)

    assert document.decode('utf-8') == data.decode('utf-8')
