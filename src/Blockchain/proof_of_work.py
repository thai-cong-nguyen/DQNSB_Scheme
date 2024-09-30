import hashlib
import sys

class Proof_Of_Work:
    def __init__(self, data, target_bits, nonce) -> None:
        self.data = data # data for a proof
        self.target_bits = target_bits # numbers of leading zero
        self.nonce = nonce

    # compute performs a PoW
    def compute(self):
        target = self.new_target()
        print("Target:", target)
        max_nonce = sys.maxsize # max size of 64 bits
        for nonce in range(max_nonce): 
            hash_int = int.from_bytes(self.hash_data(nonce), byteorder='big')
            if (hash_int < target):
                self.nonce = nonce
                break

    # returns the hash value of data||nonce
    def hash_data(self, nonce): 
        return hashlib.sha256(self.data + str(nonce).encode('utf-8')).digest()

    # checks if the PoW fulfills the requirement of Proof-of-Work
    def is_valid(self) -> bool:
        hash_int = int.from_bytes(self.hash_data(self.nonce), byteorder='big')
        target = self.new_target()
        return hash_int < target    
    
    # return a new target number with required leading zero
    def new_target(self):
        return 1 << (256 - self.target_bits)
