from flask import Flask, jsonify, request
from flask_socketio import SocketIO

app = Flask(__name__)

class Node:
    def __init__(self, node_id, shard_id, elastico_network):
        self.node_id = node_id
        self.shard_id = shard_id
        self.elastico_network = elastico_network

    def broadcast_transaction(self, transaction):
        # Logic to broadcast transaction to other nodes
        print(f"Node {self.node_id} broadcasting transaction: {transaction}")

# Simulate node joining the network
node = Node(node_id=1, shard_id=0, elastico_network=None)

@app.route('/broadcast', methods=['POST'])
def broadcast():
    data = request.json
    transaction = data.get('transaction')
    node.broadcast_transaction(transaction)
    return jsonify({"status": "Transaction broadcasted successfully"}), 200

@app.route('/run_consensus', methods=['POST'])
def run_consensus():
    # Example: Running PBFT consensus
    node.elastico_network.run_consensus_in_shard(node.shard_id, "Block from Node API")
    return jsonify({"status": "PBFT consensus started"}), 200

if __name__ == '__main__':
    app.run(port=5000)
