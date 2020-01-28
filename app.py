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
#   * Step 1: Refactor the below and put in its own project
#   * Step 2: Rewrite below to make more sense as a document store. Should be straight forward for the initial part.
#   Hard part will be the trees, and the public/private key implementation to figure out what a document is a part of.
#   * Step 3: Build a querying language BCQL/BQL, similar to a REST api to run CRUD statements, see Mongo???
########################################################################################################################

class Blockchain:

    def __init__(self):
        self.chain = []
        self.document = []
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'document': self.document
        }
        # empty list once put into the block
        self.document = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

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

    def add_transaction(self, sender, version, document):
        self.document.append({
            'key': sender,
            'version': version,
            'document': document
        })

        previous_block = self.get_previous_block()
        return previous_block['index']+1

    def add_node(self, address):
        parsed_url = urlparse(address)
        # it's the port see urllib docs
        self.nodes.add(parsed_url.netloc)

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
    blockchain.add_transaction(node_address, 'J', 1)
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
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/add_transaction', method=['POST'])
def add_transaction():
    json_file = requests.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']

    if not all(key in json_file for key in transaction_keys):
        return 'something is missing', 400

    index = blockchain.add_transaction(json_file['sender'], json['receiver'], json['amount'])
    response = {'message': f'Index of block {index}'}
    return jsonify(response), 201


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
    replace_chain_bool= blockchain.replace_chain()

    if replace_chain_bool:
        return jsonify({'message': 'Chain has been updated', 'new_chain': blockchain.chain}), 200
    else:
        return jsonify({'message': 'Chain is up to date', 'chain': blockchain.chain}), 200


app.run(host='0.0.0.0', port=5000)