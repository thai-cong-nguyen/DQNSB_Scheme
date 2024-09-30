from proof_of_work import Proof_Of_Work
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import elastico_pb2
from PBFT_node import PBFT_Node
import math
import hashlib
import time
import random

# ELASTICO combined with PBFT consensus
class ELASTICO:
    def __init__(self, num_shards, nodes_per_shard, difficulty, f) -> None:
        # Number of shards
        self.num_shards = num_shards  
        # Number of nodes in each shard
        self.nodes_per_shard = nodes_per_shard  
        # List of shards, each containing PBFT nodes
        self.shards = []  
        # List of all nodes
        self.nodes = []  
        # Fault tolerance
        self.f = f  
        # Difficulty for PoW
        self.difficulty = difficulty
        self.initialize_shards()

    # Simulate the generation of randomness for the current epoch.
    def generate_epoch_randomness(self):
        return hashlib.sha256(str(random.randint(0, 1000000)).encode('utf-8')).digest()

    # Initialize shards with PBFT nodes and assign them based on identity
    def initialize_shards(self):
        # Generate randomness for the epoch
        epoch_randomness = self.generate_epoch_randomness()
        for shard_id in range(self.num_shards):
            shard_nodes = []
            for i in range(self.nodes_per_shard):
                # Generate public-private key pair for each node
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # Create PBFT node with identity setup
                node = PBFT_Node(
                    node_id=i, 
                    # Assign IPs based on node_id
                    ip_address=f"localhost:{3000 + i}",  
                    public_key=public_key,
                    epoch_randomness=epoch_randomness,
                    difficulty=self.difficulty,
                    total_replicas=self.nodes_per_shard,
                    f=self.f
                )
                shard_nodes.append(node)
                self.nodes.append(node)  # Track all nodes across shards
            self.shards.append(shard_nodes)  # Add the shard's nodes

    # Run PBFT consensus within the specified shard
    def run_consensus_in_shard(self, shard_id, request):
        # Assume the first node is the primary
        primary_node = self.shards[shard_id][0]
        print(f"Running PBFT in Shard {shard_id} with Primary Node {primary_node.node_id}")
        primary_node.pre_prepare(request)

# # Initialize ELASTICO with PBFT and Identity Setup
# elastico_pbft = ELASTICO(num_shards=3, nodes_per_shard=4, difficulty=5, f=1)

# # Run consensus on shard 0
# elastico_pbft.run_consensus_in_shard(0, "Block of transactions for Shard 0")
