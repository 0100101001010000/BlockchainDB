import pytest
import json
import base64
from BlockchainDB import app
import uuid
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384

# TODO: Test errors!
# TODO: Test replace chain, test network updating, test that the chain updates on startup, test connect node


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


class TestCoreFunctionality:
    def test_get_chain(self, client):
        chain = client.get('/get_chain')
        assert b'{"chain":[{"database key":0,"document":{},"index":1,"previous_hash":"0","proof":1' in chain.data


class TestQuerying:
    def test_create_document(self, client):
        database_key = str(uuid.uuid4())
        chain = client.post('/create_document', json={
            'database key': database_key,
            'document': 'test_create_document test document',
            'signature': 'Open'
        })
        assert b'Document successfully created' in chain.data

    def test_create_multiple_documents(self, client):
        database_key = str(uuid.uuid4())
        chain = client.post('/create_documents', json={
            'database key': database_key,
            'documents': {
                'document1': 'test_create_multiple_documents test document 1',
                'document2': 'test_create_multiple_documents test document 2',
                'document3': 'test_create_multiple_documents test document 3',
                'document4': 'test_create_multiple_documents test document 4',
                'document5': 'test_create_multiple_documents test document 5',
            },
            'signature': 'Open'
        })
        assert b'Documents successfully created' in chain.data

    def test_get_latest(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_documents', json={
            'database key': database_key,
            'documents': {
                'document1': 'test_get_latest test document 1',
                'document2': 'test_get_latest test document 2',
                'document3': 'test_get_latest test document 3',
                'document4': 'test_get_latest test document 4',
                'document5': 'test_get_latest test document 5',
            },
            'signature': 'Open'
        })

        assert b'Documents successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc1_key = json_file['document keys']['document1']['document key']

        chain = client.post('/get_latest', json={
            'database key': database_key,
            'document key': doc1_key
        })

        assert b'Document successfully retrieved' in chain.data

    def test_get_version(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_documents', json={
            'database key': database_key,
            'documents': {
                'document1': 'test_get_version test document 1',
                'document2': 'test_get_version test document 2',
                'document3': 'test_get_version test document 3',
                'document4': 'test_get_version test document 4',
                'document5': 'test_get_version test document 5',
            },
            'signature': 'Open'
        })

        assert b'Documents successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc1_key = json_file['document keys']['document1']['document key']

        chain = client.post('/get_version', json={
            'database key': database_key,
            'document key': doc1_key,
            'version': 0
        })

        assert b'Document version 0 successfully retrieved' in chain.data

        doc_update = client.post('/update_document', json={
            'database key': database_key,
            'document key': doc1_key,
            'document': 'test_update_document test document update',
            'signature': 'Open'
        })

        assert b'Document successfully updated' in doc_update.data

        updated_chain = client.post('/get_version', json={
            'database key': database_key,
            'document key': doc1_key,
            'version': 1
        })

        assert b'Document version 1 successfully retrieved' in updated_chain.data

    def test_get_all_versions(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_documents', json={
            'database key': database_key,
            'documents': {
                'document1': 'test_get_versions test document 1',
                'document2': 'test_get_versions test document 2',
                'document3': 'test_get_versions test document 3',
                'document4': 'test_get_versions test document 4',
                'document5': 'test_get_versions test document 5',
            },
            'signature': 'Open'
        })

        assert b'Documents successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc1_key = json_file['document keys']['document1']['document key']

        chain = client.post('/get_all_versions', json={
            'database key': database_key,
            'document key': doc1_key
        })

        assert b'All document versions successfully retrieved' in chain.data

        doc_update = client.post('/update_document', json={
            'database key': database_key,
            'document key': doc1_key,
            'document': 'test_update_document test document update',
            'signature': 'Open'
        })

        assert b'Document successfully updated' in doc_update.data

        chain_update = client.post('/get_all_versions', json={
            'database key': database_key,
            'document key': doc1_key
        })

        assert b'All document versions successfully retrieved' in chain_update.data

    def test_get_all_db_documents(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_documents', json={
            'database key': database_key,
            'documents': {
                'document1': 'test_get_all_db_documents test document 1',
                'document2': 'test_get_all_db_documents test document 2',
                'document3': 'test_get_all_db_documents test document 3',
                'document4': 'test_get_all_db_documents test document 4',
                'document5': 'test_get_all_db_documents test document 5',
            },
            'signature': 'Open'
        })

        assert b'Documents successfully created' in doc_creation.data

        chain = client.post('/get_all_db_documents', json={
            'database key': database_key
        })

        assert b'All documents successfully retrieved' in chain.data

    def test_update_document(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_document', json={
            'database key': database_key,
            'document': 'test_update_document test document',
            'signature': 'Open'
        })

        assert b'Document successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc_key = json_file['document key']

        chain = client.post('/update_document', json={
            'database key': database_key,
            'document key': doc_key,
            'document': 'test_update_document test document update',
            'signature': 'Open'
        })

        assert b'Document successfully updated' in chain.data

    def test_delete_document(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_document', json={
            'database key': database_key,
            'document': 'test_delete_document test document',
            'signature': 'Open'
        })

        assert b'Document successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc_key = json_file['document key']

        chain = client.post('/delete_document', json={
            'database key': database_key,
            'document key': doc_key,
            'signature': 'Open'
        })

        assert b'Document successfully deleted' in chain.data

    def test_resurrect_document(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_document', json={
            'database key': database_key,
            'document': 'test_resurrect_document test document',
            'signature': 'Open'
        })

        assert b'Document successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc_key = json_file['document key']

        doc_deletion = client.post('/delete_document', json={
            'database key': database_key,
            'document key': doc_key,
            'signature': 'Open'
        })

        assert b'Document successfully deleted' in doc_deletion.data

        chain = client.post('/resurrect_document', json={
            'database key': database_key,
            'document key': doc_key,
            'signature': 'Open'
        })

        assert b'Document successfully resurrected' in chain.data

    def test_restore_document(self, client):
        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_document', json={
            'database key': database_key,
            'document': 'test_restore_document test document',
            'signature': 'Open'
        })

        assert b'Document successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc_key = json_file['document key']

        doc_update = client.post('/update_document', json={
            'database key': database_key,
            'document key': doc_key,
            'document': 'test_update_document test document update',
            'signature': 'Open'
        })

        assert b'Document successfully updated' in doc_update.data

        chain = client.post('/restore_document', json={
            'database key': database_key,
            'document key': doc_key,
            'version': 0
        })

        assert b'Document successfully restored' in chain.data


class TestEncryption:
    def test_string_encryption(self, client):
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

    def test_digital_signature(self, client):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("test_digital_signature_private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("test_digital_signature_receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        message = b'test_digital_signature'

        # sign
        signature_key = RSA.import_key(open("test_digital_signature_private.pem").read())
        signer = pkcs1_15.new(signature_key)
        hash_sign = SHA384.new()
        hash_sign.update(message)
        signature = signer.sign(hash_sign)

        # verify
        verification_key = RSA.import_key(open("test_digital_signature_receiver.pem").read())
        verifier = pkcs1_15.new(verification_key)
        hash_verify = SHA384.new()
        hash_verify.update(message)
        verifier.verify(hash_verify, signature)

        # test message tampering
        with pytest.raises(ValueError):
            tampered_message = message + b' this message has been tampered'
            verification_key = RSA.import_key(open("test_digital_signature_receiver.pem").read())
            verifier = pkcs1_15.new(verification_key)
            hash_verify = SHA384.new()
            hash_verify.update(tampered_message)
            verifier.verify(hash_verify, signature)

        # test incorrect key
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("test_digital_signature_private_wrong.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("test_digital_signature_receiver_wrong.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        with pytest.raises(ValueError):
            verification_key = RSA.import_key(open("test_digital_signature_receiver_wrong.pem").read())
            verifier = pkcs1_15.new(verification_key)
            hash_verify = SHA384.new()
            hash_verify.update(message)
            verifier.verify(hash_verify, signature)

    def test_encrypted_document_upload(self, client):
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
        doc_creation = client.post('/create_document', json={
            'database key': database_key,
            'document': b64encoded_string,
            'signature': 'open'
        })

        assert b'Document successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc_key = json_file['document key']

        chain = client.post('/get_latest', json={
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
        decrypted_document = cipher_aes_retrieved.decrypt_and_verify(ciphertext_retrieved, tag_retrieved)

        assert document.decode('utf-8') == decrypted_document.decode('utf-8')

    def test_document_signature(self, client):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("test_document_signature_private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("test_document_signature_receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        document = b'test_create_document test document'

        # sign
        signature_key = RSA.import_key(open("test_document_signature_private.pem").read())
        signer = pkcs1_15.new(signature_key)
        hash_sign = SHA384.new()
        hash_sign.update(document)
        signature = signer.sign(hash_sign)

        database_key = str(uuid.uuid4())
        doc_creation = client.post('/create_document', json={
            'database key': database_key,
            'document': document,
            'signature': base64.b64encode(signature)
        })

        assert b'Document successfully created' in doc_creation.data

        json_file = json.loads(doc_creation.data)
        doc_key = json_file['document key']

        chain = client.post('/get_latest', json={
            'database key': database_key,
            'document key': doc_key
        })

        assert b'Document successfully retrieved' in chain.data

        json2_file = json.loads(chain.data)
        retrieved_signature = base64.b64decode(json2_file['document']['signature'])

        verification_key_string = open("test_document_signature_receiver.pem").read()
        verification_key = RSA.import_key(verification_key_string)
        verifier = pkcs1_15.new(verification_key)
        hash_verify = SHA384.new()
        hash_verify.update(json2_file['document']['document'].encode('utf-8'))
        verifier.verify(hash_verify, retrieved_signature)

        updated_chain = client.post('/update_document', json={
            'database key': database_key,
            'document key': doc_key,
            'document': 'test_update_document test document update',
            'signature': base64.b64encode(signature),
            'public key': verification_key_string
        })

        assert b'Document successfully updated' in updated_chain.data
