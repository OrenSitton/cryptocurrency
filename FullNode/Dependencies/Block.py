"""
Author: Oren Sitton
File: Block.py
Python Version: 3
"""

from Dependencies.Transaction import Transaction
from Dependencies.methods import calculate_hash, hexify


class Block:
    """
    Block class, used to get and append blocks from Blockchain

    Attributes
    ----------
    block_number : int

    timestamp : int
        posix timestamp of when block was created
    difficulty : int
        difficulty of the block
    nonce : int
        block's nonce
    prev_hash : str
        hash of the previous block in the blockchain
    merkle_root_hash : str
        merkle tree of the block's transactions root hash
    transactions : list
        list of the block's transactions
    self_hash : str
        hash of the block

    Methods
    -------
    __init__(block)
        initiator for Block object
    network_format()
        returns the block in the network format

    Static Methods
    --------------
    from_network_format(message)
        returns a Block object from a network format message
    """

    def __init__(self, block):
        """
        initiator for Block object
        :param block: block from Blockchain
        :type block: tuple
        """
        if not isinstance(block, tuple):
            raise TypeError("Block.__init__: expected block to be of type tuple")
        self.block_number = block[1]
        self.timestamp = block[2]
        self.difficulty = block[3]
        self.nonce = int(block[4])
        self.prev_hash = block[5]
        self.merkle_root_hash = block[6]

        self.transactions = block[7]

        if isinstance(self.transactions, str):
            self.transactions = self.transactions.split(",")
        else:
            self.transactions = self.transactions.decode().split(",")
        for x in range(len(self.transactions)):
            self.transactions[x] = Transaction.from_network_format(self.transactions[x])
        self.self_hash = block[8]

    def network_format(self):
        """
        returns the Block in the network format
        :return: block in the network format
        :rtype: str
        """
        network_format = "d{}{}{}{}{}{}{}".format(hexify(self.block_number, 2), hexify(self.timestamp, 8),
                                                  hexify(self.difficulty, 2), hexify(self.nonce, 64), self.prev_hash,
                                                  self.merkle_root_hash, hexify(len(self.transactions), 2))
        for transaction in self.transactions:
            network_format += hexify(len(transaction.network_format()), 5) + transaction.network_format()
        return network_format

    @staticmethod
    def from_network_format(message):
        """
        returns a Block object from a network format message
        :param message: block message
        :type message: str
        :return: Block object from network message
        :rtype: Block
        """
        if not isinstance(message, str):
            raise TypeError("Block.from_network_format: expected message to be of type str")
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
