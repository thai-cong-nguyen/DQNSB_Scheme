import hashlib
import time
import random
import elastico_pb2
from proof_of_work import Proof_Of_Work

# Practical Byzantine Fault Tolerance (PBFT)
# Split into 3 phases: Pre-prepare - Prepare - Commit
# This allow replicas to reach a consensus even if some replicas (< 1/3) are Byzantine faulty
class PBFT_Node:
    def __init__(self, node_id, ip_address, public_key, epoch_randomness, difficulty,total_replicas, f, primary_id=None):
        self.node_id = node_id
        # ID = H(epochRandomness ‖ IP ‖ PK ‖ Nonce)
        self.ip_address = ip_address
        self.public_key = public_key
        self.epoch_randomness = epoch_randomness
        self.difficulty = difficulty
        self.total_replicas = total_replicas
        # Byzantine fault tolerance (f is the number of faulty nodes allowed)
        self.f = f  
        # if this is a primary node => primary_id = node_id
        self.primary_id = primary_id if primary_id else node_id
        # Represents the state of this node
        self.state = {}
        # Log of received messages and decisions
        self.log = []
        # Tracks the view (change if the primary fails)
        self.view_number = 0
        # Prepared status
        self.prepared = False  
        # Committed status
        self.committed = False  
        # Generate the identity for the node
        self.identity_proof = self.generate_identity_proofs()

    def generate_identity_proofs(self) -> elastico_pb2.IDProof:
        data = self.epoch_randomness + (self.ip_address).encode('utf-8') + self.public_key
        # Perform Proof-of-Work to find the Nonce such that ID < 2^γ-D
        proof_of_work = Proof_Of_Work(data, self.difficulty, 0)
        proof_of_work.compute()
        nonce = proof_of_work.nonce
        # Generate the identity hash using the formula: 
        # ID = H(epochRandomness ‖ IP ‖ PK ‖ Nonce)
        id_data = data + str(nonce).encode('utf-8')
        identity_hash = hashlib.sha256(id_data).hexdigest()
        # Check that the PoW solution is valid (ID < threshold) 
        # threshold = 1 << (256 - difficulty)
        if proof_of_work.is_valid():
            # Store the identity
            self.identity = identity_hash  
            print(f"Node {self.node_id} has generated a valid identity: {identity_hash}")
        else:
            raise Exception(f"Node {self.node_id}: Failed to generate valid identity with PoW.")
        # Return the generated identity proof (you can customize this for further use if needed)
        return {
            'Address': self.ip_address,
            'PublicKey': self.public_key,
            'Nonce': nonce,
            'IdentityHash': identity_hash
        }

    def pre_prepare(self, request):
        # Primary proposes the request to all nodes
        if self.node_id == self.primary_id:
            pre_prepare_message = {
                'phase': 'PRE-PREPARE',
                'view_number': self.view_number,
                'block': request,  # Block of transactions
                'digest': self.compute_digest(request)
            }
            self.log.append(pre_prepare_message)
            self.broadcast_prepare(pre_prepare_message)
            print(f"Node {self.node_id} In PRE-PREPARE phase")
        else:
            print(f"Node {self.node_id}: Only the primary can initiate the pre-prepare phase.")

    def broadcast_prepare(self, pre_prepare_message):
        # Replicas receive the PRE-PREPARE message and broadcast PREPARE
        if pre_prepare_message['digest'] == self.compute_digest(pre_prepare_message['block']):
            prepare_message = {
                'phase': 'PREPARE',
                'view_number': self.view_number,
                'block_digest': pre_prepare_message['digest'],
                'replica_id': self.node_id
            }
            self.log.append(prepare_message)
            # Move to prepare phase and broadcast prepare message to other nodes
            self.commit(pre_prepare_message)
            print(f"Node {self.node_id} In PREPARE phase")
        else:
            print(f"Node {self.node_id}: Invalid digest in PRE-PREPARE.")

    def commit(self, prepare_message):
        # Replicas enter commit phase after verifying enough prepare messages
        # Normally, each node should receive f+1 PREPARE messages before moving to commit
        prepare_count = sum(1 for msg in self.log if msg['phase'] == 'PREPARE' and msg['block_digest'] == prepare_message['digest'])
        # We need at least 2f+1 messages to commit
        if prepare_count >= 2 * self.f + 1:
            commit_message = {
                'phase': 'COMMIT',
                'view_number': self.view_number,
                'block_digest': prepare_message['digest'],
                'replica_id': self.node_id
            }
            self.log.append(commit_message)
            self.committed = True
            print(f"Node {self.node_id} has committed the block: {prepare_message['block']}")
        else:
            print(f"Node {self.node_id}: Waiting for more prepare messages.")

    def compute_digest(self, block):
        # Compute a digest (hash) of the block of transactions
        return hashlib.sha256(str(block).encode('utf-8')).hexdigest()
    
    
