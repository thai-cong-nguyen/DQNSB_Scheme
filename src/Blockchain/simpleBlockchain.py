import hashlib
import time
import cmd

class Transaction:
    def __init__(self, index, sender, receiver, value, block_index):
        self.index = index
        self.block_index = block_index
        self.sender = sender
        self.receiver = receiver
        self.value = value
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        tx_string = f"{self.index}{self.block_index}{self.sender}{self.receiver}{self.value}"
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def __str__(self):
        return (
            f"Transaction: {self.index}\n"
            f'TransactionHash: {self.hash}\n'
            f'Block: {self.block_index}\n'
            f"{self.sender} -> {self.receiver}: {self.value} Wei")

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0) -> None:
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        target_prefix = '0' * difficulty
        while not self.hash.startswith(target_prefix):
            self.nonce += 1
            self.hash = self.calculate_hash()

    def __str__(self) -> str:
        transactions_str = "\n".join([str(tx) for tx in self.transactions])
        return (
            f"Block: {self.index}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Transactions:\n{transactions_str}\n"
            f"Previous Hash: {self.previous_hash}\n"
            f"Hash: {self.hash}\n"
            f"Nonce: {self.nonce}\n"
            f"{'-' * 30}\n"
        )

class Blockchain:
    def __init__(self, difficulty) -> None:
        self.chain = []
        self.difficulty = difficulty

    def create_genesis_block(self) -> Block: 
        return Block(0, "0", time.time(), [], "Genesis Block")

    def is_valid(self) -> bool:
        for i in range (1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            if current_block.previous_hash != previous_block.hash:
                return False
            if current_block.hash != current_block.calculate_hash():
                return False
        return True        
    
    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def add_block(self, new_block) -> None:
        new_block.previous_hash = self.chain[len(self.chain) - 1].hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)


