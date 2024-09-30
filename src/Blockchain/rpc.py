from flask import Flask, jsonify
from ELASTICO_PBFT import ELASTICO

app = Flask(__name__)
elastico_pbft = ELASTICO(num_shards=3, nodes_per_shard=4, difficulty=5, f=1)

@app.route('/connect/<int:node_id>', methods=['GET'])
def connect_node(node_id):
    if node_id < len(elastico_pbft.nodes):
        return jsonify({"message": f"Node {node_id} connected to the blockchain."}), 200
    else:
        return jsonify({"error": "Node does not exist"}), 404

@app.route('/run_consensus/<int:shard_id>', methods=['GET'])
def run_consensus(shard_id):
    if shard_id < len(elastico_pbft.shards):
        elastico_pbft.run_consensus_in_shard(shard_id, "Block from API")
        return jsonify({"message": f"Consensus run in shard {shard_id}."}), 200
    else:
        return jsonify({"error": "Shard does not exist"}), 404

if __name__ == '__main__':
    app.run(debug=True)
