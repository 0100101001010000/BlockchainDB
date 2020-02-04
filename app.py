from flask import Flask, jsonify
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
#   * Implement Merkel trees
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
#   * Add a ressurect to change from dead back to alive
#   * Step 1: Refactor the below and put in its own project - DONE
#   * Step 2: Rewrite below to make more sense as a document store. Should be straight forward for the initial part.
#   Hard part will be the trees, and the public/private key implementation to figure out what a document is a part of.
#   Add shit ton of comments!!!
#   Some kind of shared hash needs to be stored and then verified if it is unique, get people to type in a name,
#   check uniqueness and then hash it, then need to store some kind of key to ensure that only certain people can insert
#   against it
#   Document needs to be able to accept any format, probably just accept json, needs a key so that the same "file" can
#   can be updated in a db but generates new key for db so you have a db/document key pair for updates.
#   * Step 3: Build a querying language BCQL/BQL, similar to a REST api to run CRUD statements, see Mongo???
########################################################################################################################


class Blockchain:

    def __init__(self):
        self.chain = []
        self.database_key = 0
        self.document = []
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()

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
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
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
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexidigest()
            if hash_operation[:4] == '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    # Document Creation #
    # TODO: Check that document_key doesn't exist in the db, it really shouldn't but who knows
    def create_document(self, database_key, document):
        document_key = str(uuid.uuid4())
        previous_document = self.get_document(database_key, document_key, False)
        if previous_document != 900:
            return 200
        self.database_key = database_key
        self.document.append({
            'document_key': document_key,
            'version': 0,
            'is_alive': True,
            'document': document
        })
        return 100, document_key

    # TODO: Find a more efficient way to do this
    def create_multiple_documents(self, database_key, documents):
        failures = []
        document_keys = []
        for document in documents:
            return_codes = self.create_document(database_key, document)
            for return_code, document_key in return_codes:
                if return_code != 100:
                    failures.append(
                        {
                            'document': document,
                            'error': return_code
                        }
                    )
                document_keys.append(
                    {
                        'document_key': document_key,
                        'document': document
                    }
                )
        if len(failures) != 0:
            if len(failures) == len(documents):
                return 202
            return 201, failures, document_keys
        return 101, document_keys

    # Document Queries #
    # simple select latest #
    def read_document(self, database_key, document_key, version=0):
        # TODO: going to be the most complicated as need to be able to understand various user queries
        previous_document = self.get_document(database_key, document_key, True, version)
        return previous_document

    # Document Updates #
    def update_document(self, database_key, document_key, document):
        previous_document = self.get_document(database_key, document_key, False)
        if previous_document == 900:
            return 900
        if previous_document['is_alive']:
            self.document.append(
                {
                    'database_key': database_key,
                    'document_key': document_key,
                    'version': previous_document['version']+1,
                    'is_alive': True,
                    'document': document
                }
            )
            return 500
        return 600

    def update_multiple_documents(self, database_key, documents_keys_pair):
        failures = []
        for key, document in documents_keys_pair:
            return_code = self.update_document(database_key, key, document)
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
        previous_document = self.get_document(database_key, document_key, False)
        if previous_document == 900:
            return 900
        if not previous_document['is_alive']:
            return 800
        self.document.append(
            {
                'database_key': database_key,
                'document_key': document_key,
                'version': previous_document['version']+1,
                'is_alive': False,
                'document': previous_document['document']
            }
        )
        return 700

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

    # TODO: Implement queries
    def get_document(self, database_key, document_key, read, version=0):
        chain = self.chain
        # TODO: Use a better searching algorithm
        # TODO: Check efficiency
        if not read:
            for block in sorted(chain, reverse=True):
                if block['database_key'] == database_key & block['document']['document_key'] == document_key:
                    return block['document']
            return 901
        return 900

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


# Flask
app = Flask(__name__)

# create an address for the node on port 5000
node_address = str(uuid.uuid4()).replace('-', '')

blockchain = Blockchain()


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


# This isn't needed
@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200


# Create a document
@app.route('/create_document', method=['POST'])
def add_transaction():
    json_file = requests.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']

    if not all(key in json_file for key in transaction_keys):
        return 'something is missing', 400

    index = blockchain.create_document(json_file['sender'], json['receiver'], json['amount'])
    response = {'message': f'Index of block {index}'}
    return jsonify(response), 201

# TODO: Add Read Method, Update method, and Delete method, we'll need to check keys at this point and only allow users
# with the correct keys to run the method or return an error


@app.route('/connect_node', method=['POST'])
def connect_node():
    json_file = requests.get_json()
    nodes = json_file.get('nodes')

    if nodes is None:
        return 'No node', 400

    for node in nodes:
        blockchain.add_node(node)

    response = {'message': 'Nodes connected', 'node_list': list(blockchain.nodes)}

    return jsonify(response), 201


@app.route('/replace_chain', method=['GET'])
def replace_chain():
    replace_chain_bool = blockchain.replace_chain()

    if replace_chain_bool:
        return jsonify({'message': 'Chain has been updated', 'new_chain': blockchain.chain}), 200
    else:
        return jsonify({'message': 'Chain is up to date', 'chain': blockchain.chain}), 200


app.run(host='0.0.0.0', port=5000)
