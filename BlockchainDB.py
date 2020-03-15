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
        self.document = {}
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()

    # TODO: Create can be done better, for chains that don't need to be put on a queue no need for this...
    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'database key': self.database_key,
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
            self.document = {
                'document key': document_key,
                'version': 0,
                'is alive': True,
                'document': self.encrypt_document(document)
            }
        else:
            self.document = {
                'document key': document_key,
                'version': 0,
                'is alive': True,
                'document': document
            }
        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        self.create_block(proof, previous_hash)

        return {'return code': 100, 'return info': document_key}

    def create_multiple_documents(self, database_key, documents, encrypt):
        result = {}
        for document in documents:
            created_document = self.create_document(database_key, documents[document], encrypt)

            result.update(
                {
                    document: {
                        'document key': created_document['return info'],
                        'document': documents[document]
                    }
                }
            )

        return result

    # Document Queries #
    # simple select latest #
    def get_latest(self, database_key, document_key):
        return self.get_document(database_key, document_key, 'latest')

    # select specific version #
    def get_specific_document_version(self, database_key, document_key, version):
        return self.get_document(database_key, document_key, 'version', version)

    # select all versions of a document #
    def get_all_document_versions(self, database_key, document_key):
        latest_document = self.get_document(database_key, document_key, 'latest')

        if latest_document['return code'] != 300:
            return latest_document

        latest_version = latest_document['return info']['version']

        documents_history = {f'version {latest_version}': latest_document}

        for version in range(latest_version):
            current_document = self.get_document(database_key, document_key, 'version', version)
            if current_document['return code'] != 300:
                return current_document
            documents_history = {f'version {current_document["return info"]["version"]}': current_document}

        return {'return code': 301, 'return info': documents_history}

    # select all documents from a database but only latest version #
    def get_all_documents(self, database_key):
        return self.get_document(database_key, 0, 'all latest')

    # Document Updates #
    def update_document(self, database_key, document_key, document, encrypt):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document['return code'] != 300:
            return previous_document

        self.database_key = database_key

        if previous_document['return info']['document']:
            if encrypt:
                self.document = {
                        'document key': document_key,
                        'version': previous_document['return info']['version'] + 1,
                        'is alive': True,
                        'document': self.encrypt_document(document)
                    }
            else:
                self.document = {
                        'document key': document_key,
                        'version': previous_document['return info']['version'] + 1,
                        'is alive': True,
                        'document': document
                    }

            previous_block = self.get_previous_block()
            previous_proof = previous_block['proof']
            proof = self.proof_of_work(previous_proof)
            previous_hash = self.hash(previous_block)
            self.create_block(proof, previous_hash)

            return {'return code': 500, 'return message': 'Document successfully updated'}
        return {'return code': 600, 'return message': 'Issue updating the document'}

    # Document Deletion #
    def delete_document(self, database_key, document_key):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document['return code'] != 300:
            return previous_document

        if not previous_document['return info']['is alive']:
            return {'return code': 800, 'return message': 'Document is already dead'}

        self.database_key = database_key

        self.document = {
                'document key': document_key,
                'version': previous_document['return info']['version'] + 1,
                'is alive': False,
                'document': previous_document['return info']['document']
            }

        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        self.create_block(proof, previous_hash)

        return {'return code': 700, 'return message': 'Document successfully deleted'}

    # Resurrect a document - Don't do multiple as this should probably only be done one at a time #
    def resurrect_document(self, database_key, document_key):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document == 900:
            return 900
        if not previous_document[1]['is_alive']:
            self.document.append(
                {
                    'document key': document_key,
                    'version': previous_document[1]['version'] + 1,
                    'is alive': True,
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
            for block in sorted(chain, key=lambda x: x['index'], reverse=True):
                if block['database key'] == database_key and block['document']['document key'] == document_key:
                    return {
                        'return code': 300,
                        'return info': block['document']
                    }
            return {
                'return code': 901,
                'return info': 'Document not found'
            }
        elif query == 'version':
            for block in chain:
                print(block)
                print(version)
                if block['database key'] == database_key and block['document']['document key'] == document_key and block['document']['version'] == version:
                    return {
                        'return code': 300,
                        'return info': block['document']
                    }
            return {
                'return code': 902,
                'return info': 'Document version not found'
            }
        elif query == 'all latest':
            documents = {}
            for block in sorted(chain, key=lambda x: x['index'], reverse=True):
                if block['database key'] == database_key and block['document']['document key'] not in documents:
                    documents[block['document']['document key']] = block['document']
            if documents != {}:
                return {
                    'return code': 301,
                    'return info': documents
                }
            return {
                'return code': 903,
                'return info': 'Documents not found'
            }
        else:
            return {
                'return code': 910,
                'return info': 'Query invalid'
            }


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
@app.route('/create_document', methods=['POST'])
def create_document():
    json_file = request.get_json()
    if json_file is None:
        return f'Error - {json_file}'

    transaction_keys = ['database key', 'document', 'encrypt']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})

    document_key = blockchain.create_document(json_file['database key'], json_file['document'], json_file['encrypt'])
    if document_key['return code'] == 100:
        response = {
            'message': 'Document successfully created',
            'document key': document_key["return info"]
        }
        return jsonify(response)
    else:
        response = {
            'message': f'{document_key["return code"]}, issue creating document: {document_key["return info"]}'
        }
        return jsonify(response)


@app.route('/create_documents', methods=['POST'])
def create_documents():
    json_file = request.get_json()
    transaction_keys = ['database key', 'documents', 'encrypt']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})

    document_keys = blockchain.create_multiple_documents(json_file['database key'], json_file['documents'],
                                                         json_file['encrypt'])

    response = {
        'message': 'Documents successfully created',
        'document keys': document_keys
    }

    return jsonify(response)


@app.route('/get_latest', methods=['POST'])
def get_latest():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == '':
        return jsonify({'message': 'Please provide a document key'})

    document = blockchain.get_latest(json_file['database key'], json_file['document key'])

    if document['return code'] == 300:
        response = {
            'message': 'Document successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document["return info"]}'}
        return jsonify(response)


# get_specific_document_version(self, database_key, document_key, version):
@app.route('/get_version', methods=['POST'])
def get_version():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key', 'version']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == '':
        return jsonify({'message': 'Please provide a document key'})
    elif json_file['version'] is None:
        return jsonify({'message': 'Please provide a version'})

    document = blockchain.get_specific_document_version(json_file['database key'], json_file['document key'],
                                                        json_file['version'])

    if document['return code'] == 300:
        response = {
            'message': f'Document version {json_file["version"]} successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document, returned error: {document["return info"]}'}
        return jsonify(response)


# get_all_document_versions(self, database_key, document_key)
@app.route('/get_all_versions', methods=['POST'])
def get_all_versions():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == '':
        return jsonify({'message': 'Please provide a document key'})

    document = blockchain.get_all_document_versions(json_file['database key'], json_file['document key'])

    if document['return code'] == 301:
        response = {
            'message': f'All document versions successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document["return info"]}'}
        return jsonify(response)


# get_all_documents(self, database_key)
@app.route('/get_all_db_documents', methods=['POST'])
def get_all_db_documents():
    json_file = request.get_json()
    transaction_keys = ['database key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})

    document = blockchain.get_all_documents(json_file['database key'])

    if document['return code'] == 301:
        response = {
            'message': f'All documents successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return jsonify(response)


# update_document(self, database_key, document_key, document, encrypt)
@app.route('/update_document', methods=['POST'])
def update_document():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key', 'document', 'encrypt']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == 0:
        return jsonify({'message': 'Please provide a document key'})
    elif json_file['document'] is None:
        return jsonify({'message': 'Please provide a document'})

    document = blockchain.update_document(json_file['database key'], json_file['document key'], json_file['document'],
                                          json_file['encrypt'])

    if document == 500:
        response = {
            'message': f'Document successfully updated'
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document: {document}'}
        return jsonify(response)


# delete_document(self, database_key, document_key)
@app.route('/delete_document', methods=['POST'])
def delete_document():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == 0:
        return jsonify({'message': 'Please provide a document key'})

    document = blockchain.delete_document(json_file['database key'], json_file['document key'])

    if document['return code'] == 700:
        response = {
            'message': f'Document successfully deleted'
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue deleting the document: {document}'}
        return jsonify(response)


# resurrect_document(self, database_key, document_key)
@app.route('/resurrect_document', methods=['POST'])
def resurrect_document():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'

    document = blockchain.resurrect_document(json_file['database key'], json_file['document key'])

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
    transaction_keys = ['database key', 'document key', 'version']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'
    elif json_file['version'] is None:
        return 7003, 'Please provide a version'

    document = blockchain.restore_document(json_file['database key'], json_file['document key'], json_file['version'])

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
    transaction_keys = ['database key', 'document key', 'encryption']

    if not all(key in json_file for key in transaction_keys):
        return 7000, 'Incorrect format provided',

    if json_file['database key'] == 0:
        return 7001, 'Please provide a db key'
    elif json_file['document_keys'] == 0:
        return 7002, 'Please provide a document key'
    elif json_file['encryption'] is None:
        return 7003, 'Please provide a version'

    document = blockchain.change_document_encryption(json_file['database key'], json_file['document key'],
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
