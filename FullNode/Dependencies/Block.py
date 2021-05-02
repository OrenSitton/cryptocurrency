"""
Author: Oren Sitton
File: Block.py
Python Version: 3
Description: 
"""

from Dependencies.Transaction import Transaction
from hashlib import sha256


def hexify(number, length):
    """
    calculates hexadecimal value of the number, with prefix zeroes to match length
    :param number: number to calculate hex value for, in base 10
    :type number: int
    :param length: requested length of hexadecimal value
    :type length: int
    :return: hexadecimal value of the number, with prefix zeroes
    :rtype: str
    :raise Exception: ValueError (message size is larger than length)
    """
    if not isinstance(number, int):
        raise TypeError("Transaction.hexify(number, length): expected number to be of type int")
    if not isinstance(length, int):
        raise TypeError("Transaction.hexify(number, length): expected length to be of type int")
    if number < 0:
        raise ValueError("Transaction.hexify(number, length): expected non-negative value for number, received {} "
                         "instead".format(number))
    if length < 0:
        raise ValueError("Transaction.hexify(number, length): expected non-negative value for length, received {} "
                         "instead".format(length))

    hex_base = hex(number)[2:]

    if len(hex_base) <= length:
        hex_base = (length - len(hex_base)) * "0" + hex_base
        return hex_base
    else:
        raise ValueError("Transaction.hexify(number, length): message size is larger than length")


def calculate_hash(merkle_root_hash, prev_block_hash, nonce):
    value = "{}{}{}".format(prev_block_hash, merkle_root_hash, nonce)
    return sha256(value.encode()).hexdigest()


class Block:
    def __init__(self, block):
        self.block_number = block[1]
        self.timestamp = block[2]
        self.difficulty = block[3]
        self.nonce = int(block[4])
        self.prev_hash = block[5]
        self.merkle_root_hash = block[6]
        self.transactions = block[7].decode().split(",")
        for x in range(len(self.transactions)):
            self.transactions[x] = Transaction.from_network_format(self.transactions[x])
        self.self_hash = block[8]

    def network_format(self):
        network_format = "d{}{}{}{}{}{}{}".format(hexify(self.block_number, 2), hexify(self.timestamp, 8),
                                                  hexify(self.difficulty, 2), hexify(self.nonce, 64), self.prev_hash,
                                                  self.merkle_root_hash, hexify(len(self.transactions), 2))
        for transaction in self.transactions:
            network_format += hexify(len(transaction.network_format()), 5) + transaction.network_format()
        return network_format

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
