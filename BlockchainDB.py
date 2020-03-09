from flask import Flask, jsonify, request
import datetime
import hashlib
import json
from urllib.parse import urlparse
import requests
import uuid


########################################################################################################################
# TODO:
#   * Add dependency to mine the block immediately for private chains. For public chains maybe store multiple documents
#   into one "transaction", depending on size, but one insert/update per block could work. Start with one per block.
#   * To start for each insert/update it will mine the block, can't be too difficult as you'd only mine it when using
#   * Implement Merkel trees to check chain validity and if block can be added
#   * Use public/private keys to use to differentiate the different tables/queries, for public chain, so that an insert
#   or update only 'impacts' the area desired. Instead of wallets, you'd have "table/db" access based on keys, so
#   when you have Merkel trees implemented you can only extract that "tables" that relate to you and other people can't
#   update/insert into you "db/table" without your keys. Private key would be a db, you distribute various public keys
#   public key a is read/write, public key b is read only, and unless you share it no one can see it?
#   * SQL style querying language needs to be built to retrieve the data from the chain, use gas to ensure people don't
#   run stupid queries
#   * Make the call from the python rest api, have most of the data in there, so url/insert{nosql_body}, all that the
#   code needs to do is handle saving of body to block chain and figuring out (thanks to public/private keys) how to
#   keep all things related together
#   * Encrypt document so that not everyone can read it, allow update to change the hashing algo
#   * allow for fully decrypted parts of the chain for open data, but find a way so that not everyone can amend it
#   * Next: Hard part will be the trees, and the public/private key implementation to figure out what a document is a part of.
#   Add shit ton of comments!!!
#   Some kind of shared hash needs to be stored and then verified if it is unique, get people to type in a name,
#   check uniqueness and then hash it, then need to store some kind of key to ensure that only certain people can insert
#   against it
#   Document needs to be able to accept any format, probably just accept json, needs a key so that the same "file" can
#   can be updated in a db but generates new key for db so you have a db/document key pair for updates.
########################################################################################################################


class Blockchain:

    def __init__(self):
        self.chain = []
        self.database_key = 0
        self.document = []
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()

    # TODO: Create can be done better, for chains that don't need to be put on a queue no need for this...
    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'database_key': self.database_key,
            'document': self.document
            # add database_key and document_key here?
        }
        # empty list once put into the block, must be a more efficient way to do this
        self.database_key = 0
        self.document = []
        self.chain.append(block)
        return block

    # No need for previous block per, chang to be previous hash?
    def get_previous_block(self):
        return self.chain[-1]

    # This is going to need to be adapted to the new chain
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    # should be able to change this into something simpler
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        if block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof ** 2 - previous_proof ** 2).encode()).hexidigest()
            if hash_operation[:4] == '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_node(self, address):
        parsed_url = urlparse(address)
        # it's the port see urllib docs
        self.nodes.add(parsed_url.netloc)

    # TODO: find a clean way to integrate this into the code, it will probably need to be separate
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            response = requests.get(f'http://127.0.0.1:{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    longest_chain = chain
                    max_length = length

        if longest_chain:
            self.chain = longest_chain
            return True

        return False

    # TODO: Once you understand encryption this needs to be done
    def encrypt_document(self, document):
        return document
        # return hashlib.sha256(document).encode().hexidigest()

    def decrypt_document(self, document):
        return document
        # return hashlib.sha256(document).decode()

    # Document Creation #
    # TODO: Handle existing key better, just try it again, in a while loop or something
    # TODO: Pass in public key for encryption, if below it true
    # TODO: Encrypt document and make it optional, default it to encrypt and if no key is provided then fail
    def create_document(self, database_key, document, encrypt):
        document_key = str(uuid.uuid4())
        # previous_document = self.get_document(database_key, document_key, 'latest')
        # if previous_document != 901:
        #    return 200, 'Error - Document key already exists!'
        self.database_key = database_key
        if encrypt:
            self.document.append({
                'document_key': document_key,
                'version': 0,
                'is_alive': True,
                'document': self.encrypt_document(document)
            })
        else:
            self.document.append({
                'document_key': document_key,
                'version': 0,
                'is_alive': True,
                'document': document
            })
        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        self.create_block(proof, previous_hash)

        return {100, document_key}

    # TODO: Find a more efficient way to do this
    def create_multiple_documents(self, database_key, documents, encrypt):
        result = []
        for document in documents:
            created_document = self.create_document(database_key, documents[document], encrypt)

            for returned in created_document:
                #                if return_code != 100:
                #                   failures.append(
                #                      {
                #                         'document': documents[document],
                #                        'error': return_code
                #                   }
                #              )
                result.append(
                    {
                        'document_key': created_document[returned],
                        'document': documents[document]
                    }
                )
        return result
        # if len(failures) != 0:
        #    if len(failures) == len(documents):
        #        return 202, failures
        #    return 201, document_keys, failures
        # return 101, document_keys

    # Document Queries #
    # simple select latest #
    def get_latest(self, database_key, document_key):
        return self.get_document(database_key, document_key, 'latest')

    # select specific version #
    def get_specific_document_version(self, database_key, document_key, version):
        if version is None:
            return 401
        document = self.get_document(database_key, document_key, 'version', version)
        return document

    # select all versions of a document #
    def get_all_document_versions(self, database_key, document_key):
        documents_history = self.get_document(database_key, document_key, 'latest')
        latest_version = documents_history[1]['version']

        for version in range(latest_version):
            documents_history.append(self.get_document(database_key, documents_history, 'version', version))

        if not documents_history:
            return 402
        return 300, documents_history

    # select multiple documents from a database but only latest version #
    def get_multiple_latest(self, database_key, document_keys):
        return self.get_documents(database_key, document_keys, 'latest')

    # select all documents from a database but only latest version #
    def get_all_documents(self, database_key):
        return self.get_documents(database_key, 0, 'all latest')

    # select specific versions for multiple documents #
    # TODO: Is this needed?
    def get_specific_document_versions(self, database_key, document_keys_version_pair):
        documents = []
        for document_key, version in document_keys_version_pair:
            documents.append(self.get_specific_document_version(database_key, document_key, version))
        return documents

    # select multiple documents and all versions from a db #
    # TODO: Same here, people should just loop through?
    def get_multiple_documents_and_versions(self, database_key, document_keys):
        documents = []
        for document_key in document_keys:
            documents.append(self.get_all_document_versions(database_key, document_key))
        return documents

    # select all documents and all versions from a db #
    # TODO: Same here, people should just loop through?
    def get_all_documents_and_versions(self, database_key):
        return self.get_documents(database_key, 0, 'all')

    # Document Updates #
    def update_document(self, database_key, document_key, document, encrypt):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document == 900:
            return 900
        if previous_document[1]['is_alive']:
            if encrypt:
                self.document.append(
                    {
                        'database_key': database_key,
                        'document_key': document_key,
                        'version': previous_document[1]['version'] + 1,
                        'is_alive': True,
                        'document': self.encrypt_document(document)
                    }
                )
            else:
                self.document.append(
                    {
                        'database_key': database_key,
                        'document_key': document_key,
                        'version': previous_document[1]['version'] + 1,
                        'is_alive': True,
                        'document': document
                    }
                )
            return 500
        return 600

    # TODO: Is this needed or should people loop through?
    def update_multiple_documents(self, database_key, documents_keys_pair, encrypt):
        failures = []
        for key, document in documents_keys_pair:
            return_code = self.update_document(database_key, key, document, encrypt)
            if return_code != 500:
                failures.append(
                    {
                        'key': key,
                        'error': return_code
                    }
                )
        if len(failures) != 0:
            if len(failures) == len(documents_keys_pair):
                return 602
            return 601, failures
        return 501

    # Document Deletion #
    def delete_document(self, database_key, document_key):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document == 900:
            return 900
        if not previous_document[1]['is_alive']:
            return 800
        self.document.append(
            {
                'database_key': database_key,
                'document_key': document_key,
                'version': previous_document[1]['version'] + 1,
                'is_alive': False,
                'document': previous_document[1]['document']
            }
        )
        return 700

    # TODO: Is this needed or should people loop through?
    def delete_multiple_documents(self, database_key, document_keys):
        failures = []
        for key in document_keys:
            return_code = self.delete_document(database_key, key)
            if return_code != 700:
                failures.append(
                    {
                        'key': key,
                        'error': return_code
                    }
                )
        if len(failures) != 0:
            if len(document_keys) == len(failures):
                return 802
            return 801, failures
        return 701

    # Resurrect a document - Don't do multiple as this should probably only be done one at a time #
    def resurrect_document(self, database_key, document_key):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document == 900:
            return 900
        if not previous_document[1]['is_alive']:
            self.document.append(
                {
                    'database_key': database_key,
                    'document_key': document_key,
                    'version': previous_document[1]['version'] + 1,
                    'is_alive': True,
                    'document': previous_document[1]['document']
                }
            )
            return 1000
        return 2000

    # Restore a specific document version #
    def restore_document(self, database_key, document_key, version):
        old_document = self.get_specific_document_version(database_key, document_key, version)
        return_code = self.update_document(database_key, document_key, old_document, False)

        if return_code == 500:
            return 3000
        return 4000

    # Just encrypt/decrypt text document #
    def change_document_encryption(self, database_key, document_key, encryption):
        document = self.get_latest(database_key, document_key)

        if encryption == 'encrypt':
            return_code = self.update_document(database_key, document_key, document, True)
        elif encryption == 'decrypt':
            return_code = self.update_document(database_key, document_key, self.decrypt_document(document), False)
        else:
            return 6000

        if return_code == 500:
            return 5000
        return 6001

    def get_document(self, database_key, document_key, query, version=0):
        # TODO: Only store the db instead of the chain? Would make it more efficient to run multiple queries against
        #  same db
        chain = self.chain
        # TODO: Use a better searching algorithm
        # TODO: Check efficiency
        if query == 'latest':
            for block in sorted(chain, reverse=True):
                if block['database_key'] == database_key and block['document']['document_key'] == document_key:
                    return 300, block['document']
            return 901
        elif query == 'version':
            for block in chain:
                if block['database_key'] == database_key and block['document']['document_key'] == document_key and \
                        block['document']['version'] == version:
                    return block['document']
                return 902
        else:
            return 910

    # TODO: Only allow queries from the same db key for now
    def get_documents(self, database_key, document_keys, query, versions=0):
        chain = self.chain
        documents = []
        if query == 'latest':
            for block in sorted(chain, reverse=True):
                if block['database_key'] == database_key and block['document']['document_key'] in document_keys:
                    documents.append(block['document'])
            if not documents:
                return 903
        elif query == 'version':
            for block in chain:
                if block['database_key'] == database_key and block['document']['document_key'] in document_keys and \
                        block['document']['version'] in versions:
                    documents.append(block['document'])
            if not documents:
                return 904
        elif query == 'all latest':
            for block in sorted(chain, reverse=True):
                # TODO: Do more efficiently...
                if block['database_key'] == database_key:
                    for document in documents:
                        if block['document']['document_key'] != document['version']:
                            documents.append(block['document'])
            if not documents:
                return 905
        elif query == 'all':
            for block in chain:
                if block['database_key'] == database_key:
                    documents.append(block['document'])
            if not documents:
                return 905
        else:
            return 910

        if not documents:
            return 999
        return 301, documents


########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################

# TODO: Redo all of this

# Flask
app = Flask(__name__)

# create an address for the node on port 5000
node_address = str(uuid.uuid4()).replace('-', '')

blockchain = Blockchain()


# TODO: No longer needed?
@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    blockchain.create_document(node_address, 'J', 1)
    response = {
        'message': 'Congratulations, you just mined a block',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'transactions': block['transactions']
    }
    return jsonify(response), 200


# TODO: Find a better way to do this, this is only needed for replace chain
@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/connect_node', methods=['POST'])
def connect_node():
    json_file = request.get_json(force=True)
    nodes = json_file.get('nodes')

    if nodes is None:
        return 'No node', 400

    for node in nodes:
        blockchain.add_node(node)

    response = {'message': 'Nodes connected', 'node_list': list(blockchain.nodes)}

    return jsonify(response), 201


@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    replace_chain_bool = blockchain.replace_chain()

    if replace_chain_bool:
        return jsonify({'message': 'Chain has been updated', 'new_chain': blockchain.chain}), 200
    else:
        return jsonify({'message': 'Chain is up to date', 'chain': blockchain.chain}), 200


## Queries ##
# Create a document
# create_document(self, database_key, document, encrypt)
@app.route('/create_document', methods=['POST'])
def create_document():
    json_file = request.get_json()
    if json_file is None:
        return f'Error - {json_file}'

    transaction_keys = ['database_key', 'document', 'encrypt']

    if not all(key in json_file for key in transaction_keys):
        return '7000 , Incorrect format provided'

    if json_file['database_key'] == 0:
        return '7001 ,lease provide a db key'

    document_key = blockchain.create_document(json_file['database_key'], json_file['document'], json_file['encrypt'])
    if document_key[0] == 100:
        response = {'message': f'New key for document: {document_key[1]}'}
        # return f'100 , {jsonify(response)}'
        return jsonify(response)
    else:
        response = {'message': f'Issue creating document: {document_key[1]}'}
        return f'{document_key[0]}, Issue creating document: {document_key[1]}'  # {jsonify(response)}


# create_multiple_documents(self, database_key, documents, encrypt)
@app.route('/create_documents', methods=['POST'])
def create_documents():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'documents', 'encrypt']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided'

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'

    document_keys = blockchain.create_multiple_documents(json_file['database_key'], json_file['documents'],
                                                         json_file['encrypt'])

    if document_keys[0] == 101:
        response = {'message': f'New keys for document: {document_keys[1]}'}
        return 101, jsonify(response)
    elif document_keys[0] == 201:
        response = {
            'message': f'Issue creating some of the documents: {document_keys[2]}, but some were created {document_keys[1]}'}
        return 201, jsonify(response)
    elif document_keys[0] == 202:
        response = {'message': f'Issue creating all documents: {document_keys[1]}'}
        return 202, jsonify(response)
    else:
        response = {'message': f'Unknown issue: {document_keys}'}
        return 203, jsonify(response)


# get_latest(self, database_key, document_key)#
@app.route('/get_latest', methods=['POST'])
def get_latest():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_key'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.get_latest(json_file['database_key'], json_file['document_key'])

    if document[0] == 300:
        response = {
            'message': 'Document successfully retrieved',
            'document': document[1]
        }
        return 300, jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return 400, jsonify(response)


# get_specific_document_version(self, database_key, document_key, version):
@app.route('/get_version', methods=['POST'])
def get_version():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key', 'version']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_key'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.get_specific_document_version(json_file['database_key'], json_file['document_key'],
                                                        json_file['version'])

    if document[0] == 300:
        response = {
            'message': f'Document version {json_file["version"]} successfully retrieved',
            'document': document[1]
        }
        return 300, jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return 400, jsonify(response)


# get_all_document_versions(self, database_key, document_key)
@app.route('/get_all_version', methods=['POST'])
def get_all_versions():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_key'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.get_all_document_versions(json_file['database_key'], json_file['document_key'])

    if document[0] == 301:
        response = {
            'message': f'All document versions successfully retrieved',
            'document': document[1]
        }
        return 300, jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return 400, jsonify(response)


# get_multiple_latest(self, database_key, document_keys)
@app.route('/get_multiple_documents', methods=['POST'])
def get_multiple_documents():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_keys']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.get_multiple_latest(json_file['database_key'], json_file['document_key'])

    if document[0] == 301:
        response = {
            'message': f'All documents successfully retrieved',
            'document': document[1]
        }
        return 301, jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return 400, jsonify(response)


# get_all_documents(self, database_key)
@app.route('/get_all_db_documents', methods=['POST'])
def get_all_db_documents():
    json_file = request.get_json()
    transaction_keys = ['database_key']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'

    document = blockchain.get_all_documents(json_file['database_key'])

    if document[0] == 301:
        response = {
            'message': f'All documents successfully retrieved',
            'document': document[1]
        }
        return 300, jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return 400, jsonify(response)


# update_document(self, database_key, document_key, document, encrypt)
@app.route('/update_document', methods=['POST'])
def update_document():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key', 'document', 'encrypt']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'
    elif json_file['document'] is None:
        return 7003, 'Please provide a document'

    document = blockchain.update_document(json_file['database_key'], json_file['document_key'], json_file['document'],
                                          json_file['encrypt'])

    if document == 500:
        response = {
            'message': f'Document successfully updated'
        }
        return 500, jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document: {document}'}
        return 600, jsonify(response)


# delete_document(self, database_key, document_key)
@app.route('/delete_document', methods=['POST'])
def delete_document():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.delete_document(json_file['database_key'], json_file['document_key'])

    if document == 700:
        response = {
            'message': f'Document successfully deleted'
        }
        return 700, jsonify(response)
    else:
        response = {'message': f'Issue deleting the document: {document}'}
        return 800, jsonify(response)


# resurrect_document(self, database_key, document_key)
@app.route('/resurrect_document', methods=['POST'])
def resurrect_document():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.resurrect_document(json_file['database_key'], json_file['document_key'])

    if document == 1000:
        response = {
            'message': f'Document successfully resurrected'
        }
        return 1000, jsonify(response)
    else:
        response = {'message': f'Issue resurrecting the document: {document}'}
        return 2000, jsonify(response)


# restore_document(self, database_key, document_key, version)
@app.route('/restore_document', methods=['POST'])
def restore_document():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key', 'version']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'
    elif json_file['version'] is None:
        return 7003, 'Please provide a version'

    document = blockchain.restore_document(json_file['database_key'], json_file['document_key'], json_file['version'])

    if document == 3000:
        response = {
            'message': f'Document successfully restored'
        }
        return 3000, jsonify(response)
    else:
        response = {'message': f'Issue restoring the document: {document}'}
        return 4000, jsonify(response)


# change_document_encryption(self, database_key, document_key, encryption)
@app.route('/change_encryption', methods=['POST'])
def change_encryption():
    json_file = request.get_json()
    transaction_keys = ['database_key', 'document_key', 'encryption']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database_key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'
    elif json_file['encryption'] is None:
        return 7003, 'Please provide a version'

    document = blockchain.change_document_encryption(json_file['database_key'], json_file['document_key'],
                                                     json_file['encryption'])

    if document == 5000:
        response = {
            'message': f'Encryption successfully changed'
        }
        return 5000, jsonify(response)
    else:
        response = {'message': f'Issue changing the encryption: {document}'}
        return 6000, jsonify(response)


app.run(host='0.0.0.0', port=5000)


def for_tests():
    test_app = Flask(__name__)
    test_app.run(host='0.0.0.0', port=5000)
