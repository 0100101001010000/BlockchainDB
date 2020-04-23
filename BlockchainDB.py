import base64
import os

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from flask import Flask, jsonify, request
import datetime
import hashlib
import json
from urllib.parse import urlparse
import requests
import uuid
import threading
import logging

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


class BlockchainDB:
    def __init__(self):
        self.chain = []
        self.database_key = 0
        self.document = {}
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()
        logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
        logging.info('Starting chain...')

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'database key': self.database_key,
            'document': self.document
        }
        self.database_key = 0
        self.document = []
        self.chain.append(block)
        logging.debug(f'New block created: \n {block}')
        return block

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            # Why does the below take 2 minutes longer to run???
            # hash_operation = SHA256.new()
            # hash_operation.update(str(new_proof ** 2 - previous_proof ** 2).encode())
            # hash_operation = hash_operation.hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

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
            hash_operation = hashlib.sha256(str(proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_node(self, address, current_node):
        node = urlparse(address).netloc
        if node in self.nodes or node is None:
            return
        self.nodes.add(node)
        logging.debug(f'New node added: {node}')
        self.update_chain()
        # ensure that this node gets added to the other node
        requests.post(f'http://{node}/connect_node', json={"nodes": [f"{current_node}"]})

    def replace_chain(self, chain):
        if self.is_chain_valid(chain) and len(self.chain) < len(chain):
            self.chain = chain
            logging.info('This chain has been replaced')
            update_thread = threading.Thread(target=blockchainDB.update_network,
                                             args=(chain[-1]['database key'], chain[-1]['document']['document key']))
            update_thread.start()
            return True
        else:
            logging.warning('There has been an attempt to update this chain with an invalid chain')
            return False

    def update_network(self, database_key, document_key):
        network = self.nodes
        current_chain_length = len(self.chain)

        for node in network:
            if node is None:
                continue
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                if database_key != self.chain[-1]['database key'] and document_key != self.chain[-1]['database key']['document key']:
                    return
                length = response.json()['length']
                chain = response.json()['chain']
                is_chain_valid = self.is_chain_valid(chain)
                does_last_block_match = False

                if chain[-1] == self.chain[-1]:
                    does_last_block_match = True

                if length > current_chain_length and is_chain_valid:
                    logging.info('This chain is being replaced, longest chain wins')
                    self.chain = chain
                    return
                elif length == current_chain_length and is_chain_valid and does_last_block_match:
                    continue
                elif length < current_chain_length and is_chain_valid and not does_last_block_match:
                    # TODO: replace other chain, seems absurd to send the entire chain? Merkel trees to only replace
                    # the section that needs to be replaced
                    logging.info(f'Updating chain at {node}')
                    replace_response = requests.post(f'http://{node}/replace_chain', json={'chain': self.chain})
                    if replace_response.status_code != 200:
                        self.nodes.remove(node)
                elif length == current_chain_length and is_chain_valid and not does_last_block_match:
                    logging.info(f'This chain and chain at {node}, don\'t match, next update wins')
                    continue

    def update_chain(self):
        logging.info('Checking for more up-to-date chains')
        network = self.nodes
        longest_chain = None
        longest_chain_length = len(self.chain)
        if not network:
            return
        # todo: stop crashing if node not connected
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > longest_chain_length and self.is_chain_valid(chain):
                    logging.info(f'Longer chain found at {node}')
                    longest_chain = chain
                    longest_chain_length = length
            else:
                self.nodes.remove(node)

        if longest_chain:
            self.chain = longest_chain
            logging.info('This chain has been replaced')

    def multiple_network_updates(self, database_key, document_keys):
        for document_key in document_keys:
            self.update_network(database_key, document_key)

    def get_latest(self, database_key, document_key):
        return self.get_document(database_key, document_key, 'latest')

    def get_specific_document_version(self, database_key, document_key, version):
        return self.get_document(database_key, document_key, 'version', version)

    def get_all_document_versions(self, database_key, document_key):
        latest_document = self.get_document(database_key, document_key, 'latest')

        if latest_document['return code'] != 300:
            return latest_document

        latest_version = latest_document['return info']['version']

        documents_history = {f'version {latest_version}': latest_document}

        for version in range(latest_version):
            current_document = self.get_document(database_key, document_key, 'version', version)
            if current_document['return code'] != 301:
                return current_document
            documents_history = {f'version {current_document["return info"]["version"]}': current_document}

        return {'return code': 301, 'return info': documents_history}

    def get_all_documents(self, database_key):
        return self.get_document(database_key, 0, 'all latest')

    def create_document(self, database_key, document, signature):
        document_key = str(uuid.uuid4())
        self.database_key = database_key
        self.document = {
            'document key': document_key,
            'version': 0,
            'is alive': True,
            'document': document,
            'signature': signature
        }
        previous_block = self.chain[-1]
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        self.create_block(proof, previous_hash)
        logging.debug('New document created')

        return {'return code': 100, 'return info': document_key}

    def create_multiple_documents(self, database_key, documents, signature):
        result = {}
        for document in documents:
            created_document = self.create_document(database_key, documents[document], signature)

            result.update(
                {
                    document: {
                        'document key': created_document['return info'],
                        'document': documents[document]
                    }
                }
            )

        return result

    def update_document(self, database_key, document_key, document, signature, public_key=b''):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document['return code'] != 300:
            return previous_document

        self.database_key = database_key

        if previous_document['return info']['document']:
            if previous_document['return info']['signature'] == 'Open':
                self.document = {
                        'document key': document_key,
                        'version': previous_document['return info']['version'] + 1,
                        'is alive': True,
                        'document': document,
                        'signature': signature
                    }
            else:
                if public_key == '':
                    return {{'return code': 201, 'return message': 'Public key cannot be empty'}}
                retrieved_signature = base64.b64decode(previous_document['return info']['signature'])
                verification_key = RSA.import_key(public_key)
                verifier = pkcs1_15.new(verification_key)
                hash_verify = SHA384.new()
                hash_verify.update(previous_document['return info']['document'].encode('utf-8'))
                try:
                    verifier.verify(hash_verify, retrieved_signature)
                except ValueError:
                    return {'return code': 202, 'return message': 'Cannot verify document'}

                self.document = {
                        'document key': document_key,
                        'version': previous_document['return info']['version'] + 1,
                        'is alive': True,
                        'document': document,
                        'signature': signature
                    }

            previous_block = self.chain[-1]
            previous_proof = previous_block['proof']
            proof = self.proof_of_work(previous_proof)
            previous_hash = self.hash(previous_block)
            self.create_block(proof, previous_hash)
            logging.debug('Document updated')

            return {'return code': 101, 'return message': 'Document successfully updated'}
        return {'return code': 200, 'return message': 'Issue updating the document'}

    def delete_document(self, database_key, document_key):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document['return code'] != 300:
            return previous_document

        if not previous_document['return info']['is alive']:
            return {'return code': 203, 'return message': 'Document is already dead'}

        self.database_key = database_key

        self.document = {
                'document key': document_key,
                'version': previous_document['return info']['version'] + 1,
                'is alive': False,
                'document': previous_document['return info']['document']
            }

        previous_block = self.chain[-1]
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        self.create_block(proof, previous_hash)

        return {'return code': 102, 'return message': 'Document successfully deleted'}

    def resurrect_document(self, database_key, document_key):
        previous_document = self.get_document(database_key, document_key, 'latest')
        if previous_document['return code'] != 300:
            return previous_document

        if previous_document['return info']['is alive']:
            return {'return code': 204, 'return message': 'Document is alive'}

        self.database_key = database_key

        self.document = {
            'document key': document_key,
            'version': previous_document['return info']['version'] + 1,
            'is alive': True,
            'document': previous_document['return info']['document']
        }

        previous_block = self.chain[-1]
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        self.create_block(proof, previous_hash)
        logging.debug('Document resurrected')

        return {'return code': 103, 'return message': 'Document successfully resurrected'}

    def restore_document(self, database_key, document_key, version):
        old_document = self.get_specific_document_version(database_key, document_key, version)
        if old_document['return code'] != 301:
            return {'return code': 205, 'return message': old_document['return info']}
        return_code = self.update_document(database_key, document_key, old_document['return info']['document'], False)

        if return_code['return code'] != 101:
            return {'return code': 206, 'return info': f'Issues restoring the document: {return_code}'}

        logging.info('Document restored')
        return {'return code': 104, 'return info': 'Document successfully restored'}

    def get_document(self, database_key, document_key, query, version=0):
        chain = self.chain
        # TODO: Use a better searching algorithm
        # TODO: Check efficiency
        if query == 'latest':
            for block in sorted(chain, key=lambda x: x['index'], reverse=True):
                if block['database key'] == database_key and block['document']['document key'] == document_key:
                    return {'return code': 300, 'return info': block['document']}
            return {'return code': 400, 'return info': 'Document not found'}
        elif query == 'version':
            for block in chain:
                print(block)
                print(version)
                if block['database key'] == database_key and block['document']['document key'] == document_key and block['document']['version'] == version:
                    return {'return code': 301, 'return info': block['document']}
            return {'return code': 401, 'return info': 'Document version not found'}
        elif query == 'all latest':
            documents = {}
            for block in sorted(chain, key=lambda x: x['index'], reverse=True):
                if block['database key'] == database_key and block['document']['document key'] not in documents:
                    documents[block['document']['document key']] = block['document']
            if documents != {}:
                return {'return code': 302, 'return info': documents}
            return {'return code': 402, 'return info': 'Documents not found'}
        else:
            return {'return code': 403, 'return info': 'Query invalid'}


########################################################################################################################

# Flask
app = Flask(__name__)

# create an address for the node on port 5000
node_address = str(uuid.uuid4()).replace('-', '')
host = '0.0.0.0'
port = 5000
blockchainDB = BlockchainDB()

# TODO: Add logging below? See how it turns out when it gets run on a machine


# TODO: No longer needed?
@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchainDB.chain[-1]
    previous_proof = previous_block['proof']
    proof = blockchainDB.proof_of_work(previous_proof)
    previous_hash = blockchainDB.hash(previous_block)
    block = blockchainDB.create_block(proof, previous_hash)
    blockchainDB.create_document(node_address, 'J', 1)
    response = {
        'message': 'Congratulations, you just mined a block',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'transactions': block['transactions']
    }
    return jsonify(response), 200


@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchainDB.chain,
        'length': len(blockchainDB.chain)
    }

    return jsonify(response), 200


@app.route('/connect_node', methods=['POST'])
def connect_node():
    json_file = request.get_json(force=True)
    nodes = json_file.get('nodes')

    if nodes is None:
        return 'No node', 400

    current_node = f'http://{host}:{port}'

    for node in nodes:
        blockchainDB.add_node(node, current_node)

    response = {'message': 'Nodes connected', 'node_list': list(blockchainDB.nodes)}

    return jsonify(response), 201


@app.route('/replace_chain', methods=['POST'])
def replace_chain():
    json_file = request.get_json()
    if json_file is None:
        return f'Error - {json_file}'

    if not json_file['chain']:
        return jsonify({'message': 'Incorrect format provided'})

    chain_replaced = blockchainDB.replace_chain(json_file['chain'])

    if chain_replaced:
        return jsonify({'message': 'Chain successfully replaced'})
    else:
        return jsonify({'message': 'Issues replacing chain'})


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

    document = blockchainDB.get_latest(json_file['database key'], json_file['document key'])

    if document['return code'] == 300:
        response = {
            'message': 'Document successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document["return info"]}'}
        return jsonify(response)


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

    document = blockchainDB.get_specific_document_version(json_file['database key'], json_file['document key'],
                                                          json_file['version'])

    if document['return code'] == 301:
        response = {
            'message': f'Document version {json_file["version"]} successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document, returned error: {document["return info"]}'}
        return jsonify(response)


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

    document = blockchainDB.get_all_document_versions(json_file['database key'], json_file['document key'])

    if document['return code'] == 301:
        response = {
            'message': f'All document versions successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document["return info"]}'}
        return jsonify(response)


@app.route('/get_all_db_documents', methods=['POST'])
def get_all_db_documents():
    json_file = request.get_json()
    transaction_keys = ['database key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})

    document = blockchainDB.get_all_documents(json_file['database key'])

    if document['return code'] == 302:
        response = {
            'message': f'All documents successfully retrieved',
            'document': document['return info']
        }
        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document {document}'}
        return jsonify(response)


@app.route('/create_document', methods=['POST'])
def create_document():
    json_file = request.get_json()
    if json_file is None:
        return f'Error - {json_file}'

    transaction_keys = ['database key', 'document', 'signature']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    if json_file['signature'] == '':
        return jsonify({'message': 'Please provide a signature'})

    document_key = blockchainDB.create_document(json_file['database key'], json_file['document'], json_file['signature'])
    if document_key['return code'] == 100:
        response = {
            'message': 'Document successfully created',
            'document key': document_key["return info"]
        }
        update_thread = threading.Thread(target=blockchainDB.update_network, args=(json_file['database key'], document_key["return info"]))
        update_thread.start()

        return jsonify(response)
    else:
        response = {
            'message': f'{document_key["return code"]}, issue creating document: {document_key["return info"]}'
        }
        return jsonify(response)


@app.route('/create_documents', methods=['POST'])
def create_documents():
    json_file = request.get_json()
    transaction_keys = ['database key', 'documents', 'signature']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    if json_file['signature'] == '':
        return jsonify({'message': 'Please provide a signature'})

    document_keys = blockchainDB.create_multiple_documents(json_file['database key'], json_file['documents'],
                                                           json_file['signature'])

    response = {
        'message': 'Documents successfully created',
        'document keys': document_keys
    }

    update_thread = threading.Thread(target=blockchainDB.multiple_network_updates,
                                     args=(json_file['database key'], document_keys))
    update_thread.start()

    return jsonify(response)


@app.route('/update_document', methods=['POST'])
def update_document():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key', 'document', 'signature']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == '':
        return jsonify({'message': 'Please provide a document key'})
    elif json_file['document'] is None:
        return jsonify({'message': 'Please provide a document'})
    if json_file['signature'] == '':
        return jsonify({'message': 'Please provide a signature'})

    if 'public key' not in json_file:
        document = blockchainDB.update_document(json_file['database key'],
                                                json_file['document key'],
                                                json_file['document'],
                                                json_file['signature'])
    else:
        document = blockchainDB.update_document(json_file['database key'],
                                                json_file['document key'],
                                                json_file['document'],
                                                json_file['signature'],
                                                json_file['public key'])

    if document == 101:
        response = {
            'message': f'Document successfully updated'
        }

        update_thread = threading.Thread(target=blockchainDB.update_network,
                                         args=(json_file['database key'], json_file['document key']))
        update_thread.start()

        return jsonify(response)
    else:
        response = {'message': f'Issue retrieving the document: {document}'}
        return jsonify(response)


@app.route('/delete_document', methods=['POST'])
def delete_document():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == '':
        return jsonify({'message': 'Please provide a document key'})

    document = blockchainDB.delete_document(json_file['database key'], json_file['document key'])

    if document['return code'] == 102:
        response = {
            'message': f'Document successfully deleted'
        }
        update_thread = threading.Thread(target=blockchainDB.update_network,
                                         args=(json_file['database key'], json_file['document key']))
        update_thread.start()

        return jsonify(response)
    else:
        response = {'message': f'Issue deleting the document: {document}'}
        return jsonify(response)


@app.route('/resurrect_document', methods=['POST'])
def resurrect_document():
    json_file = request.get_json()
    transaction_keys = ['database key', 'document key']

    if not all(key in json_file for key in transaction_keys):
        return jsonify({'message': 'Incorrect format provided'})

    if json_file['database key'] == '':
        return jsonify({'message': 'Please provide a db key'})
    elif json_file['document key'] == '':
        return jsonify({'message': 'Please provide a document key'})

    document = blockchainDB.resurrect_document(json_file['database key'], json_file['document key'])

    if document['return code'] == 103:
        response = {
            'message': f'Document successfully resurrected'
        }
        update_thread = threading.Thread(target=blockchainDB.update_network,
                                         args=(json_file['database key'], json_file['document key']))
        update_thread.start()
        return jsonify(response)
    else:
        response = {'message': f'Issue resurrecting the document: {document}'}
        return jsonify(response)


@app.route('/restore_document', methods=['POST'])
def restore_document():
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

    document = blockchainDB.restore_document(json_file['database key'], json_file['document key'], json_file['version'])

    if document == 104:
        response = {
            'message': f'Document successfully restored'
        }
        update_thread = threading.Thread(target=blockchainDB.update_network,
                                         args=(json_file['database key'], json_file['document key']))
        update_thread.start()
        return jsonify(response)
    else:
        response = {'message': f'Issue restoring the document: {document}'}
        return jsonify(response)


app.run(host=host, port=port)
