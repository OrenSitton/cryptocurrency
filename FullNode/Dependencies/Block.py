"""
Author: Oren Sitton
File: Block.py
Python Version: 3
Description: 
"""

from Dependencies import Transaction
from hashlib import sha256


def hexify(number, length):
    pass

def calculate_hash(merkle_root_hash, prev_block_hash, nonce):
    value = "{}{}{}".format(prev_block_hash, merkle_root_hash, nonce)
    return sha256(value.encode()).hexdigest()


class Block:
    def __init__(self, block):
        self.block_number = block[0]
        self.timestamp = block[1]
        self.prev_hash = block[2]
        self.difficulty = block[3]
        self.nonce = int(block[4])
        self.merkle_root_hash = block[5]
        self.transactions = block[6].decode().split(",")
        for x in range(len(self.transactions)):
            self.transactions[x] = Transaction.from_network_format(self.transactions[x])
        self.self_hash = block[7]

    def network_format(self):
        network_format = "d{}{}{}{}{}{}{}".format(hexify(self.block_number, 2), hexify(self.timestamp, 8),
                                                  hexify(self.difficulty, 2), hexify(self.nonce, 64), self.prev_hash,
                                                  self.merkle_root_hash, hexify(len(self.transactions), 2))
        for transaction in self.transactions:
            network_format += hexify(len(transaction.network_format()), 5) + transaction.network_format()

    @staticmethod
    def from_network_format(message):
        if not message[0] == 'd':
            raise ValueError()
        block_number = int(message[1:7], 16)
        timestamp = int(message[7:15], 16)
        difficulty = int(message[15:17], 16)
        nonce = int(message[17:81], 16)
        previous_block_hash = message[81:145]
        merkle_root_hash = message[145:209]
        transaction_count = int(message[209:211], 16)
        message = message[211:]
        block_transactions = []
        for x in range(transaction_count):
            transaction_length = message[:2]
            transaction = message[2:transaction_length + 2]
            block_transactions.append(transaction)
            message = message[transaction_length + 2:]
        self_hash = calculate_hash(merkle_root_hash, previous_block_hash, nonce)
        block = (block_number, timestamp, difficulty, nonce, previous_block_hash, merkle_root_hash, block_transactions)
        return Block(block)


def main():
    pass


if __name__ == '__main__':
    main()
