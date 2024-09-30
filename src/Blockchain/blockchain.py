import time
import cmd
from ELASTICO_PBFT import ELASTICO 

class BlockchainConsole(cmd.Cmd):
    prompt = 'blockchain> '
    intro = "Welcome to the Blockchain Console. Type ? to list commands"

    def __init__(self, elastico_network):
        super().__init__()
        self.network = elastico_network  # The Elastico network that nodes interact with

    def do_connect(self, line):
        """Connect a node to the blockchain"""
        node_id = int(line)
        if node_id < len(self.network.nodes):
            node = self.network.nodes[node_id]
            print(f"Node {node_id} connected to the blockchain.")
        else:
            print(f"Node {node_id} does not exist in the network.")

    def do_run_consensus(self, line):
        """Run PBFT consensus in a shard"""
        try:
            shard_id = int(line)
            if shard_id < len(self.network.shards):
                self.network.run_consensus_in_shard(shard_id, f"Block {int(time())}")
            else:
                print(f"Shard {shard_id} does not exist.")
        except ValueError:
            print("Usage: run_consensus <shard_id>")

    def do_view_identity(self, line):
        """View node's identity based on its ID"""
        node_id = int(line)
        if node_id < len(self.network.nodes):
            node = self.network.nodes[node_id]
            print(f"Node {node_id} identity: {node.identity}")
        else:
            print(f"Node {node_id} does not exist.")

    def do_exit(self, line):
        """Exit the console"""
        return True

# Initialize the ELASTICO network
elastico_pbft = ELASTICO(num_shards=3, nodes_per_shard=4, difficulty=5, f=1)

# Start the console for node interaction
console = BlockchainConsole(elastico_pbft)
console.cmdloop()