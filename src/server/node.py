from hashlib import sha256
import json
import time
from flask import Flask, request
import requests

class Block:
    def __init__(self, index, transactions, timestamp, previous_has):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_has = previous_has
        self.nonce = 0

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self, difficulty):
        self.difficulty = difficulty
        self.pending_transactions = []
        self.chain_of_blocks = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0x")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain_of_blocks.append(genesis_block)

    @property
    def last_block(self):
        return self.chain_of_blocks[-1]
    
    def add_block(self, block, proof) -> bool:
        previous_block_hash = self.last_block().hash
        if previous_block_hash != block.previous_hash:
            return False
        if not Blockchain.is_valid_proof(difficulty=self.difficulty, block=block, proof=proof):
            return False
        block.hash = proof
        self.chain_of_blocks.append(block)
        return True
    
    def proof_of_work(self, block):
        block.nonce = 0
        block_hash = block.compute_hash()
        while not block_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            block_hash = block.compute_hash()
        return block_hash
    
    def add_new_transaction(self, transaction):
        self.pending_transactions.append(transaction)
    
    @classmethod
    def is_valid_proof(cls, difficulty, block, block_hash):
        return (block_hash.startswith('0' * difficulty) and block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = '0x'

        for block in chain:
            block_hash = block.hash
            delattr(block, "hash")
            if not cls.is_valid_proof(block, block.hash) or previous_hash != block.previous_hash:
                result = False
                break
        block.hash, previous_hash = block_hash, block_hash
        return result
    
    def mine(self):
        if not self.pending_transactions:
            return False
        last_block = self.last_block()
        new_block = Block(index=last_block.index + 1, 
                          transactions=self.pending_transactions,
                          timestamp=time.time(),
                          previous_has=last_block.hash)
        proof = self.proof_of_work(new_block)
        self.add_block(block=new_block, proof=proof)

        self.pending_transactions = []
        # announce it to the network
        announce_new_block(new_block)
        return new_block.index
    
app = Flask(__name__)
print(app)

difficulty = 4
blockchain = Blockchain(difficulty)

peers = set()

@app.route("/new_transaction", methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ['author', 'content']

    print(required_fields)
    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404

    tx_data['timestamp'] = time.time()
    print(tx_data)
    blockchain.add_new_transaction(tx_data)
    return "Send transaction Successfully", 201

@app.route("/chain", methods=['GET'])
def get_chain():
    consensus()
    chain_data = []
    for block in blockchain.chain_of_blocks:
        chain_data.append(block.__dict__)
    return json.dumps({
            "length": len(chain_data),
            "chain": chain_data
        })

@app.route("/mine", methods=['GET'])
def mine_pending_transactions():
    result = blockchain.mine()
    if not result:
        return "No transactions to mine or Transactions is not valid"
    return "Block #{} is mined.".format(result)

@app.route("/add_nodes", methods=['POST'])
def register_new_peers():
    nodes = request.get_json()
    if not nodes:
        return "Invalid node data", 400
    for node in nodes:
        peers.add(node)
    return "Added nodes Successfully", 201

@app.route("/add_block", methods=['POST'])
def validate_and_add_block():
    block_data = request.get_json()
    block = Block(index=block_data['index'], transactions=block_data['transactions'], timestamp=block_data['timestamp'],previous_has=block_data['previous_has'])

    proof = block_data['hash']
    is_added = blockchain.add_block(block=block, proof=proof)

    if not is_added:
        return "The block was discarded by the node - Reason: Invalid", 400
    return "Block added to the chain", 201

@app.route("/pending_tx")
def get_pending_tx():
    return json.dumps(blockchain.pending_transactions)

@app.route("/ping")
def ping_blockchain():
    return "Ping Ping..."

def consensus():
    global blockchain
    longest_chain= None
    current_len = len(blockchain.chain_of_blocks)
    for node in peers:
        response = requests.get("http://{}/chain".format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain=chain):
            current_len = length
            longest_chain = chain
    if longest_chain:
        blockchain = longest_chain
        return True
    return False

def announce_new_block(block):
    for peer in peers:
        url = "http://{}/add_block".format(peer)
        requests.post(url, data=json.dumps(block.__dict__, sort_keys=True))

app.run(debug=True, port=8001)

