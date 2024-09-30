from proof_of_work import Proof_Of_Work
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import elastico_pb2
from PBFT_node import PBFT_Node
import math
import hashlib
import time

class ELASTICO:
    def __init__(self, random, difficulty, shardNum) -> None:
        self.random = random
        self.difficulty = difficulty
        self.shardNum = shardNum
        self.id_proof = None

    def generate_epoch_randomness(self):
        # EpochRandomness = Hash(block.timestamp) 
        # we can use previous hash instead of block.timestamp
        return hashlib.sha256(str(time.time()).encode('utf-8')).digest()

    # returns a new proof for identity with PoW
    # epoch_randomness is used to avoid malicious nodes precomputing identifies.
    def new_id_proof(self, address, public_key) -> elastico_pb2.IDProof:
        data = (self.epoch_randomness + address).encode('utf-8') + public_key
        # Compute PoW to get the nonce
        proof_of_work = Proof_Of_Work(data, self.difficulty, 0)
        proof_of_work.compute()
        nonce = proof_of_work.nonce
        self.id_proof = elastico_pb2.IDProof()
        self.id_proof.Address = address
        self.id_proof.PK = public_key
        self.id_proof.Nonce = str(nonce).encode('utf-8')
        return self.id_proof
    
    # toByte converts the identity proof to slice of byte without nonce field.
    def to_bytes(self):
        return (self.epoch_randomness + self.id_proof.Address).encode('utf-8') + self.id_proof.PK
    
    # Verify verifies if the identity proof is correct.
    def verify(self) -> bool:
        proof_to_bytes = self.id_proof.SerializeToString()
        proof_of_work = Proof_Of_Work(proof_to_bytes, self.difficulty, self.id_proof.Nonce)
        return proof_of_work.is_valid()
    
    # GetCommitteeNo generates the committee number based on the identity proof.
    def get_committee_no(self) -> int:
        proof_to_bytes = self.id_proof.SerializeToString()
        proof_of_work = Proof_Of_Work(proof_to_bytes, self.difficulty, self.id_proof.Nonce)
        hash_data = proof_of_work.hash_data(self.id_proof.Nonce)
        # Use the last `l` bits for the committee number (based on shard count)
        bit_num = math.ceil(math.log2(self.shardNum))
        last_bits = hash_data[-bit_num:]
        return int.from_bytes(last_bits, byteorder='big') % self.shardNum

def test_id_proof_verify(elastico: ELASTICO, public_key):
    elastico.new_id_proof("localhost:9388", public_key=public_key)
    print(elastico.id_proof)
    print("Verify:", elastico.verify())
    elastico.id_proof.Address = "localhost:9488"
    print("Verify:", elastico.verify())
    pass

def test_id_proof_get_committee_no(elastico: ELASTICO, public_key):
    id_proof = elastico.new_id_proof("localhost:9388", public_key=public_key)
    proof_to_bytes = id_proof.SerializeToString()
    proof_of_work = Proof_Of_Work(proof_to_bytes, elastico.difficulty, id_proof.Nonce)
    hash_data = proof_of_work.hash_data(id_proof.Nonce)
    no = elastico.get_committee_no()
    print(hash_data, no)
    pass

elastico = ELASTICO('epochRandom', 2, 10)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

test_id_proof_verify(elastico=elastico, public_key=public_key)
# test_id_proof_get_committee_no(elastico=elastico, public_key=public_key)
