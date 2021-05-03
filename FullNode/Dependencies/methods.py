"""
Author: Oren Sitton
File: methods.py
Python Version: 3
Description: methods used across multiple files
"""
from hashlib import sha256


def calculate_hash(previous_block_hash, merkle_tree_root_hash, nonce):
    """
    calculates the hash of a block based on its merkle tree root hash, previous block hash and nonce
    :param previous_block_hash: hash of the previous block in the blockchain
    :type previous_block_hash: str
    :param merkle_tree_root_hash: hash of the root of the merkle tree of the block's transactions
    :type merkle_tree_root_hash: str
    :param nonce: nonce of the block
    :type nonce: int
    :return: hash of the block
    :rtype: str
    """

    if not isinstance(previous_block_hash, str):
        raise TypeError("calculate_hash: expected prev_block_hash to be of type str")
    if not isinstance(merkle_tree_root_hash, str):
        raise TypeError("calculate_hash: expected merkle_root_hash to be of type str")
    if not isinstance(nonce, int):
        raise TypeError("calculate_hash: expected nonce to be of type int")
    value = "{}{}{}".format(previous_block_hash, merkle_tree_root_hash, nonce)
    return sha256(value.encode()).hexdigest()


def hexify(number, length):
    """
    creates hexadecimal value of the number, with prefix zeroes to be of length length
    :param number: number to calculate hex value for, in base 10
    :type number: int
    :param length: requested length of hexadecimal value
    :type length: int
    :return: hexadecimal value of the number, with prefix zeroes
    :rtype: str
    :rtype: str
    :raise: ValueError: message size is larger than length
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
        raise ValueError("hexify: hexadecimal string size is larger than length")


def hexify_string(string):
    """
    creates hexadecimal string of the string, encoded in utf-8
    :param string: string to calculate hex value for
    :type string: str
    :return: hexadecimal string of string, encoded in utf-8
    :rtype: str
    """
    return string.encode("utf-8").hex()
