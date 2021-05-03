"""
Author: Oren Sitton
File: Full Node.py
Python Version: 3
Description:
"""
import datetime
# TODO: add TypeError exceptions to all functions & methods that receive parameters
import logging
import math
import pickle
import queue
import socket
import threading
from hashlib import sha256
from time import sleep

import select
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from Dependencies import Block
from Dependencies import Blockchain
from Dependencies import Flags
from Dependencies import SyncedArray
from Dependencies import Transaction
from Dependencies import calculate_hash
from Dependencies import hexify
from Dependencies import hexify_string

"""
Global Variables
----------------
inputs : SyncedArray
    list of current nodes connected to node's server socket
client_sockets : SyncedArray
    list of current client sockets connected to other node's server sockets
transactions : SyncedArray
    list of pending transactions
thread_queue : queue.Queue
    queue to load return value from mining thread
flags : Flags
    flags object to coordinate between threads
"""

inputs = SyncedArray(name="input list")
client_sockets = SyncedArray(name="client List")
transactions = SyncedArray(name="transaction List")
thread_queue = queue.Queue()
flags = Flags()


"""
Initiation Functions
"""


def config(key, directory="Dependencies\\config.txt"):
    """
    returns data from configuration file
    :param key: dictionary key to return value of
    :type key: str
    :param directory: directory of configuration file, default Dependencies\\config.txt
    :type directory: str
    :return: value of dictionary for key
    :rtype: Any
    :raises: FileNotFoundError: configuration file not found at directory
    :raises: TypeError: unpickled object is not a dictionary
    """
    if not isinstance(key, str):
        raise TypeError("config: expected key to be of type str")
    if not isinstance(directory, str):
        raise TypeError("config: expected directory to be of type str")
    try:
        with open(directory, "rb") as file:
            configuration = pickle.load(file)
    except FileNotFoundError:
        raise FileNotFoundError("config: configuration file not found at {}".format(directory))
    else:
        if not isinstance(configuration, dict):
            raise TypeError("config: expected file to contain pickled dict")
        else:
            return configuration.get(key)


def initialize_client(ip, port):
    """
    initializes client socket object to address and appends it to client_socket list
    :param ip: ipv4 address to initialize client socket to
    :type ip: str
    :param port: tcp port to initialize client socket to
    :type port: int
    :return: client socket object
    :rtype: socket.socket
    """
    if not isinstance(ip, str):
        raise TypeError("initialize_client: expected ip to be of type str")
    if not isinstance(port, int):
        raise TypeError("initialize_client: expected port to be of type int")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
        logging.info("[{}, {}]: Connected to node"
                     .format(client_socket.getpeername()[0], client_socket.getpeername()[1]))

    except (ConnectionRefusedError, socket.gaierror):
        logging.info("[{}, {}]: Connection attempt refused"
                     .format(ip, port))

    else:
        client_sockets.append(client_socket)


def initialize_clients(addresses, port):
    """
    initializes client socket objects to addresses and appends them to client_socket list
    :param addresses: ipv4 addresses to initialize client sockets to
    :type addresses: list
    :param port: tcp port to initialize client sockets to
    :type port: int
    """
    if not isinstance(addresses, list):
        raise TypeError("initialize_clients: expected addresses to be of type list")
    if not isinstance(port, int):
        raise TypeError("initialize_clients: expected port to be of type int")
    threads = []
    for i, address in enumerate(addresses):
        if address != config("ip_address"):
            thread = threading.Thread(name="Client Connection Thread {}".format(i + 1), target=initialize_client,
                                      args=(address, port,))
            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()

    logging.info("{} nodes accepted connection"
                 .format(len(client_sockets)))


def initialize_server(ip, port):
    """
    initializes server socket object to address
    :param ip: ipv4 address to initialize server socket to
    :type ip: str
    :param port: tcp port to initialize server socket to
    :type port: int
    :return: server socket object
    :rtype: socket.socket
    """
    if not isinstance(ip, str):
        raise TypeError("initialize_server: expected ip to be of type str")
    if not isinstance(port, int):
        raise TypeError("initialize_server: expected port to be of type int")
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setblocking(False)
        server_socket.bind((ip, port))
        server_socket.listen(5)
    except OSError:
        return None
    else:
        return server_socket


def seed_clients(dns_ip, dns_port, peer_port, **kwargs):
    """
    seeds nodes from DNS seeding server, initializes client socket objects to received addresses, and appends them to
    client_socket list
    :param dns_ip: ipv4 address of DNS seeding server
    :type dns_ip: str
    :param dns_port: tcp port of DNS seeding server
    :type dns_port: int
    :param peer_port: tcp port to initialize client sockets to
    :type peer_port: int
    :keyword attempts: amount of times to attempt connection to the DNS seeding server
    :keyword type attempts: int
    :keyword delay: seconds of delay between attempts to connect to DNS seeding server
    :keyword type delay: int
    """
    if not isinstance(dns_ip, str):
        raise TypeError("seed_clients: expected dns_ip to be of type str")
    if not isinstance(dns_port, int):
        raise TypeError("seed_clients: expected dns_port to be of type int")
    if not isinstance(peer_port, int):
        raise TypeError("seed_clients: expected peer_port to be of type int")

    if kwargs.get("attempts"):
        if not isinstance(kwargs.get("attempts"), int):
            raise TypeError("seed_clients: expected attempts to be of type int")
        attempts = kwargs.get("attempts")
    else:
        attempts = 5

    if kwargs.get("delay"):
        if not isinstance(kwargs.get("delay"), int):
            raise TypeError("seed_clients: expected delay to be of type int")
        delay = kwargs.get("delay")
    else:
        delay = 5

    peer_addresses = []
    seed_client = ""
    for x in range(attempts):
        try:
            seed_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            seed_client.connect((dns_ip, dns_port))

        except ConnectionRefusedError:
            if x == attempts - 1:
                logging.info("Seeding server did not accept connection")
                return

        else:
            break

    for x in range(attempts):
        seed_client.send("00001a".encode())
        data = seed_client.recv(5).decode()
        data = seed_client.recv(int(data, 16)).decode()

        if data[0] == "b":
            peer_addresses = []
            seed_client.close()
            peer_count = int(data[1:3], 16)
            data = data[3:]
            for peer in range(peer_count):
                ip_address = "{}.{}.{}.{}".format(
                    int(data[:2], 16), int(data[2:4], 16), int(data[4:6], 16), int(data[6:], 16)
                )
                peer_addresses.append(ip_address)
                data = data[8:]
            break
        else:
            sleep(delay)

    seed_client.close()

    logging.info("Seeding yielded {} addresses".format(len(peer_addresses)))

    initialize_clients(peer_addresses, peer_port)

    flags["finished seeding"] = True


"""
Calculation Functions
"""


def calculate_difficulty(delta_t, prev_difficulty):
    """
    calculates difficulty of blockchain block, based on previous blocks
    :param delta_t: time difference between last block group
    :type delta_t: int
    :param prev_difficulty: difficulty of blocks in previous block group
    :type prev_difficulty: int
    :return: difficulty of block based on previous blocks difficulty & delta_t
    :rtype: int
    """
    if not isinstance(delta_t, int):
        raise TypeError("calculate_difficulty: expected delta_t to be of type int")
    if not isinstance(prev_difficulty, int):
        raise TypeError("calculate_difficulty: expected prev_difficulty to be of type int")
    ratio = (1209600 / delta_t)
    difficulty_addition = math.log(ratio, 2)
    if difficulty_addition > 0:
        return prev_difficulty + math.ceil(difficulty_addition)
    elif difficulty_addition < 0 < prev_difficulty + math.floor(difficulty_addition):
        return prev_difficulty + math.floor(difficulty_addition)
    elif difficulty_addition < 0:
        return 1
    return prev_difficulty


def calculate_merkle_root_hash(block_transactions):
    """
    calculates the merkle tree root hash of the block's transactions
    :param block_transactions: list of the blocks transactions
    :type block_transactions: list
    :return: merkle tree root hash of the block's transactions
    :rtype: str
    """
    if not isinstance(block_transactions, list):
        raise TypeError("calculate_merkle_root_hash: expected block_transactions to be of type list")
    for t in block_transactions:
        if not isinstance(t, Transaction):
            raise TypeError("calculate_merkle_root_hash: expected block_transactions to be a list of type Transaction")

    block_transactions = block_transactions.copy()
    for x in range(len(block_transactions)):
        block_transactions[x] = block_transactions[x].sha256_hash()
    if not len(block_transactions):
        return "0" * 64
    while len(block_transactions) != 1:
        tmp_transactions = []
        for x in range(0, len(block_transactions) - 1, 2):
            hash1 = block_transactions[x]
            hash2 = block_transactions[x + 1]
            tmp_transactions.append(sha256("{}{}".format(hash1, hash2).encode()).hexdigest())
        block_transactions = tmp_transactions
    return block_transactions[0]


def validate_transaction(transaction, blockchain, previous_block_hash=""):
    """
    validates the transaction's format & data
    :param transaction: transaction to validate
    :type transaction: Transaction
    :param blockchain: blockchain to use to check transaction's validity
    :type blockchain: Blockchain
    :param previous_block_hash: hash of the previous block (for transactions we
                                want to validate not in the consensus chain) default="" for consensus chain transactions
    :type previous_block_hash: str
    :return: True if the transaction is valid, False if not
    :rtype: tuple
    """
    if not isinstance(transaction, Transaction):
        raise TypeError("validate_transaction: expected transaction to be of type Transaction")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("validate_transaction: expected blockchain to be of type Blockchain")
    if not isinstance(previous_block_hash, str):
        raise TypeError("validate_transaction: expected previous_block_hash to be of type str")

    if validate_transaction_format(transaction)[0]:
        if previous_block_hash:
            return validate_transaction_data(transaction, blockchain, previous_block_hash)
        else:
            return validate_transaction_data_consensus(transaction, blockchain)
    return validate_transaction_format(transaction)


def validate_transaction_data(transaction, blockchain, previous_block_hash):
    """
    validates the transaction's data
    :param transaction: transaction to validate
    :type transaction: Transaction
    :param blockchain: blockchain to use to check transaction's validity
    :type blockchain: Blockchain
    :param previous_block_hash: hash of the previous block
    :type previous_block_hash: str
    :return: True if transaction is valid, False if not
    :rtype: tuple
    """
    # validate input sources and signatures
    input_amount = 0
    output_amount = 0

    for input1 in transaction.inputs:
        block = ""
        if input1[1] < blockchain.__len__() - 1:
            block = blockchain.get_block_consensus_chain(input1[1])
        elif input1[1] == blockchain.__len__():
            block = blockchain.get_block_by_hash(previous_block_hash)
        elif input1[1] == blockchain.__len__() - 1:
            block = blockchain.get_block_by_hash(blockchain.get_block_by_hash(previous_block_hash).prev_hash)
        input_transaction = block.transactions[input1[2] - 1]

        appears = False

        for source_output in input_transaction:
            if source_output[0] == input1[0]:
                appears = True
                input_amount += source_output[1]

        if not appears:
            return False, "transaction input's source does not appear in source block"

        hasher = SHA256.new(transaction.signing_format().encode("utf-8"))
        verifier = PKCS1_v1_5.new(RSA.import_key(input1[0]))
        if not verifier.verify(hasher, input1[3]):
            return False, "signature is not valid"

    # input sources and signatures are valid, check that input amount equals output amount
    for output in transaction.outputs:
        output_amount += output[1]

    if not output_amount - input_amount:
        return False, "input and output amounts are not equal"

    # input amount equals output amounts, validate that no transactions are a double spend
    for input1 in transaction.inputs:
        for x in range(input1[1] + 1, len(blockchain) + 1):
            block = ""
            if x < blockchain.__len__() - 1:
                block = blockchain.get_block_consensus_chain(x)
            elif x == blockchain.__len__():
                block = blockchain.get_block_by_hash(previous_block_hash)
            elif x == blockchain.__len__() - 1:
                block = blockchain.get_block_by_hash(blockchain.get_block_by_hash(previous_block_hash).prev_hash)
            for block_transaction in block.transactions:
                for input2 in block_transaction.inputs:
                    if input2[0] == input1[0] and input2[1] == input1[1] and input2[2] == input1[2]:
                        return False, "double spend"

    return True, ""


def validate_transaction_data_consensus(transaction, blockchain):
    """
    validates the transaction's data
    :param transaction: transaction to validate
    :type transaction: Transaction
    :param blockchain: blockchain to use to check transaction's validity
    :type blockchain: Blockchain
    :return: True if transaction is valid, False if not
    :rtype: tuple
    """
    # validate input sources and signatures
    input_amount = 0
    output_amount = 0

    for input1 in transaction.inputs:
        block = blockchain.get_block_consensus_chain(input1[1])
        input_transaction = block.transactions[input1[2] - 1]

        appears = False

        for source_output in input_transaction:
            if source_output[0] == input1[0]:
                appears = True
                input_amount += source_output[1]

        if not appears:
            return False, "transaction input's source does not appear in source block"

        hasher = SHA256.new(transaction.signing_format().encode("utf-8"))
        verifier = PKCS1_v1_5.new(RSA.import_key(input1[0]))
        if not verifier.verify(hasher, input1[3]):
            return False, "signature is not valid"

    # input sources and signatures are valid, check that input amount equals output amount
    for output in transaction.outputs:
        output_amount += output[1]

    if not output_amount - input_amount:
        return False, "input and output amounts are not equal"

    # input amount equals output amounts, validate that no transactions are a double spend
    for input1 in transaction.inputs:
        for x in range(input1[1] + 1, len(blockchain) + 1):
            block = blockchain.get_block_consensus_chain(x)
            for block_transaction in block.transactions:
                for input2 in block_transaction.inputs:
                    if input2[0] == input1[0] and input2[1] == input1[1] and input2[2] == input1[2]:
                        return False, "double spend"

    return True, ""


def validate_transaction_format(transaction):
    """
    validates the transaction's format
    :param transaction: transaction to validate
    :type transaction: Transaction
    :return: True if the transaction is valid, False if else
    :rtype: tuple
    """
    # validate that transaction inputs are in order
    for x in range(0, len(transaction.inputs) - 1):
        if int(transaction.inputs[x][0], 16) > int(transaction.inputs[x + 1][0], 16):
            return False, "inputs order invalid"
        elif int(transaction.inputs[x][0], 16) == int(transaction.inputs[x + 1][0], 16):
            if transaction.inputs[x][1] > transaction.inputs[x + 1][1]:
                return False, "inputs order invalid"
            elif transaction.inputs[x][1] == transaction.inputs[x + 1][1]:
                if transaction.inputs[x][2] > transaction.inputs[x + 1][2]:
                    return False, "input order invalid"

    # transaction inputs are in order, validate that transaction outputs are in order\
    for x in range(0, len(transaction.outputs) - 1):
        if int(transaction.outputs[x][0], 16) > int(transaction.outputs[x][0]):
            return False, "outputs order invalid"

    # transaction outputs are in order, validate that input sources don't appear twice
    for i, input1 in enumerate(transaction.inputs):
        for j, input2 in enumerate(transaction.inputs):
            if i != j:
                if input1[0] == input2[0] and input1[1] == input2[1] and input1[2] == input1[2]:
                    return False, "input source appears twice"

    # input sources don't appear twice, validate that outputs keys don't appear twice
    for i, output1 in enumerate(transaction.outputs):
        for j, output2 in enumerate(transaction.outputs):
            if i != j:
                if output1[0] == output2[0]:
                    return False, "output key appears twice"

    # output keys don't appear twice
    return True, ""


"""
Build Message Functions
"""


def build_get_blocks_message(first_block_number, last_block_number):
    """
    builds a get blocks message
    :param first_block_number: number of first requested block
    :type first_block_number: int
    :param last_block_number: number of last requested block
    :type last_block_number: int
    :return: get bocks message
    :rtype: str
    """
    if not isinstance(first_block_number, int):
        raise TypeError("build_get_blocks_message: expected first_block_number to be of type int")
    if not isinstance(last_block_number, int):
        raise TypeError("build_get_blocks_message: expected last_block_number to be of type int")
    message = "g{}{}".format(hexify(first_block_number, 6), hexify(last_block_number, 6))
    return message


def build_error_message(error_message):
    """
    builds an error message
    :param error_message: error message to build error message for
    :type error_message: str
    :return: error message
    :rtype: str
    """
    if not isinstance(error_message, str):
        raise TypeError("build_error_message: expected error_message to be of type str")
    message = "f{}".format(hexify_string(error_message))
    return message


def build_peers_message(peers_list):
    """
    builds a peers message
    :param peers_list: list of peer ipv4 addresses
    :type peers_list: list
    :return: peer message
    :rtype: str
    """
    if not isinstance(peers_list, list):
        raise TypeError("build_peers_message: expected peers_list to be of type list")
    for p in peers_list:
        if not isinstance(p, str):
            raise TypeError("build_peers_message: expected peers_list to be a list of type str")
    message = "b{}".format(hexify(len(peers_list), 2))
    for address in peers_list:
        address_bytes = address.split(".")
        for byte in address_bytes:
            message += hexify(int(byte), 2)
    return message


"""
Handle Message Functions
"""


def handle_message(message, blockchain):
    """
    redirects message to relevant message handling function
    :param message: message to handle
    :type message: str
    :param blockchain: BLockchain to use for relevant messages 
    :type blockchain: Blockchain
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message: expected message to be of type str")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("handle_message: expected blockchain to be of type Blockchain")
    message_handling_functions = dict(a=lambda: handle_message_peers_request(),
                                      b=lambda: handle_message_peers(message),
                                      c=lambda: handle_message_block_request(message, blockchain),
                                      d=lambda: handle_message_block(message, blockchain),
                                      e=lambda: handle_message_transaction(message, blockchain),
                                      f=lambda: handle_message_error(message),
                                      g=lambda: handle_message_blocks_request(message, blockchain),
                                      h=lambda: handle_message_blocks(message, blockchain))

    message_type = message[:1]

    if message_type not in message_handling_functions:
        logging.debug("Message is invalid (unrecognized message type)")
        reply = build_error_message("unrecognized message type")
        reply = "{}{}".format(hexify(len(reply), 5), reply)
        return reply, 1
    else:
        return message_handling_functions[message_type]()


def handle_message_block(message, blockchain):
    """
    validates block message, appends it if it is valid
    :param message: block message
    :type message: str
    :param blockchain: blockchain to use to validate block and to append block to if it is valid
    :type blockchain: Blockchain
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_block: expected message to be of type str")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("handle_message_block: expected blockchain to be type Blockchain")
    try:
        block = Block.from_network_format(message)
    except ValueError:
        return None, -1

    # check if block number relevant
    if block.block_number < blockchain.__len__() - 1:
        return None, -1

    # check if block already received
    if blockchain.get_block_by_hash(block.self_hash):
        return None, -1

    # check if previous block exists
    previous_block = blockchain.get_block_by_hash(block.prev_hash)
    if not previous_block and block.block_number > blockchain.__len__():
        return build_get_blocks_message(blockchain.__len__(), block.block_number), 1
    elif not previous_block:
        return None, -1

    # validate time created
    if block.timestamp <= previous_block.timestamp:
        return None, -1

    # validate difficulty
    if block.block_number <= 2016:
        if block.difficulty != config("default difficulty"):
            return None, -1
    else:
        maximum_block = blockchain.get_block_by_hash(block.prev_hash)
        while maximum_block.block_number % 2016 != 0:
            maximum_block = blockchain.get_block_by_hash(maximum_block.prev_hash)
        minimum_block = blockchain.get_block_by_hash(maximum_block.prev_hash)
        while minimum_block.block_number % 2016 != 0:
            minimum_block = blockchain.get_block_by_hash(minimum_block.prev_hash)
        delta_t = maximum_block.timestamp - minimum_block.timestamp
        if block.difficulty != calculate_difficulty(delta_t, blockchain.get_block_by_hash(
                maximum_block.prev_hash).difficulty):
            return None, -1

    # validate nonce #
    maximum = 2 ** (256 - block.difficulty)
    b_hash = calculate_hash(block.prev_hash, block.merkle_root_hash, block.nonce)
    int_hash = int(b_hash, 16)

    if int_hash > maximum:
        return None, -1

    # validate first transaction
    if len(block.transactions[0].inputs):
        return None, -1
    elif len(block.transactions[0].outputs) != 1:
        return None, -1
    elif block.transactions[0].outputs[0][1] != config("block reward"):
        return None, -1

    # validate transactions
    for transaction in block.transactions[1:]:
        if not validate_transaction(transaction, blockchain, block.prev_hash)[0]:
            return None, -1

    # validate merkle root hash
    transaction_hash = calculate_merkle_root_hash(block.transactions)

    if block.merkle_root_hash != transaction_hash:
        return None, -1

    # validate transactions are in order
    for i in range(1, len(block.transactions) - 1):
        if block.transactions[i] < block.transactions[i + 1]:
            return None, -1

    # check for overlaps
    for t1 in range(1, len(block.transactions)):
        for t2 in range(1, len(block.transactions)):
            if not t1 == t2:
                if block.transactions[t1].overlap(block.transactions[t2]):
                    return None, -1

    # append to database
    blockchain.append(block.block_number, block.timestamp, block.difficulty, block.nonce, block.prev_hash,
                      block.merkle_root_hash, block.transactions, block.self_hash)

    # delete blocks if consensus long enough
    if blockchain.get_block_consensus_chain(blockchain.__len__()).self_hash == block.self_hash:
        # block is in consensus
        for block2 in blockchain.__getitem__(block.block_number - 2):
            if block2.self_hash != blockchain.get_block_consensus_chain(block.block_number - 2).self_hash:
                blockchain.delete(block2.self_hash)

    # raise flag if appropriate
    if blockchain.get_block_consensus_chain(blockchain.__len__()).self_hash == block.self_hash:
        flags["received new block"] = True
        logging.info("Received new block")

    # remove transactions from list if necessary
    for t in transactions:
        if not validate_transaction(t, blockchain):
            transactions.remove(t)

    # return message
    return "{}{}".format(len(block.network_format()), block.network_format())


def handle_message_block_request(message, blockchain):
    """
    validates block request message and returns appropriate reply
    :param message: block request message
    :type message: str
    :param blockchain: blockchain to use to get block
    :type blockchain: Blockchain
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_block_request: expected messge to be of type str")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("handle_message_block_request: expected blockchain to be of type Blockchain")
    if len(message) != 71:
        # message not in correct format
        logging.debug("Message is an invalid block request")
        return None, -1
    else:
        block_number = int(message[1:7], 16)
        previous_block_hash = message[7:]

        if block_number == 0 and previous_block_hash.replace("0", ""):
            # message in incorrect format
            logging.debug("Message is an invalid block request")
            return None, -1
        elif block_number == 0:
            block = blockchain.get_block_consensus_chain(blockchain.__len__())
        else:
            # return requested block if have, else return nothing
            block = blockchain.__getitem__(block_number, prev_hash=previous_block_hash)

        if block:
            reply = block.network_format()
            logging.debug("Message is a block request")
            return "{}{}".format(hexify(len(reply), 5), reply), 1
        else:
            logging.debug("Message is an invalid block request")
            return None, -1


def handle_message_blocks(message, blockchain):
    """
    validates blocks message, appends block if they are valid
    :param message: blocks message
    :type message: str
    :param blockchain: blockchain to use to validate blocks and to append blocks if they are valid
    :type blockchain: Blockchain
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_blocks: expected message to be of type str")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("handle_message_blocks: expected blockchain to be of type Blockchain")
    block_count = int(message[1:7], 16)
    message = message[7:]
    for i in range(block_count):
        block_size = message[:5]
        handle_message_block(message[5: 5 + block_size], blockchain)
        message = message[5 + block_size:]


def handle_message_blocks_request(message, blockchain):
    """
    validates blocks request message and returns appropriate reply
    :param message: blocks request message
    :type message: str
    :param blockchain: blockchain to use to get blocks
    :type blockchain: Blockchain
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_blocks_request: expected message to be of type str")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("handle_message_blocks_request: expected blockchain to be of type Blockchain")
    first_block = int(message[1:7], 16)
    last_block = int(message[7:13], 16)

    reply = "h{}".format(hexify(last_block - first_block + 1, 6))

    for i in range(first_block, last_block + 1):
        block = blockchain.get_block_consensus_chain(i)
        if block:
            reply += "{}{}".format(len(block.network_format()), block.network_format())

    return reply, 1


def handle_message_error(message):
    """
    handles error message
    :param message: error message
    :type message: str
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_error: expected message to be of type str")
    logging.debug("Message is an error message [{}]".format(message[1:]))
    return None, -1


def handle_message_peers(message):
    """
    validates peers message, connects to them if valid
    :param message: peers message
    :type message: str
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_peers: expected message to be of type str")
    if len(message) < 3:
        logging.debug("Message is an invalid peer message")
        return None, -1
    peer_count = int(message[1:3], 16)
    if len(message) < 3 + 8 * peer_count:
        logging.debug("Message is an invalid peer message")
        return None, -1
    logging.debug("Message is a peer message")
    message = message[3:]

    addresses = []

    for x in range(peer_count):
        byte1 = int(message[:2], 16)
        byte2 = int(message[2:4], 16)
        byte3 = int(message[4:6], 16)
        byte4 = int(message[6:8], 16)
        address = "{}.{}.{}.{}".format(byte1, byte2, byte3, byte4)
        addresses.append(address)
        message = message[8:]
    threading.Thread(name="Peer Seeding Thread", target=initialize_clients, args=(addresses, 8333,)).start()
    return None, -1


def handle_message_peers_request():
    """
    handles peer request message
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    logging.debug("Message is a peer request message")
    reply = build_peers_message(inputs.array)
    reply = "{}{}".format(hexify(len(reply), 5), reply)
    return reply, 1


def handle_message_transaction(message, blockchain):
    """
    validates transactions message, appends it to transactions list if valid
    :param message: transaction message
    :type message: str
    :param blockchain: blockchain to use to validate transaction
    :type blockchain: Blockchain
    :return: reply message, along with an int to specify who to reply to (-1: no one, 1: message sender, 2: all nodes)
    :rtype: tuple
    """
    if not isinstance(message, str):
        raise TypeError("handle_message_transaction: expected message to be of type str")
    if not isinstance(blockchain, Blockchain):
        raise TypeError("handle_message_transaction: expected blockchain to be of type Blockchain")
    try:
        transaction = Transaction.from_network_format(message)
    except ValueError:
        logging.debug("Message is an invalid transaction message [message format invalid]")
        return None, -1
    else:
        if transaction in transactions:
            logging.debug("Message is a previously received transaction message")
            return None, -1
        msg_validity = validate_transaction(transaction, blockchain)
        if msg_validity[0]:
            transactions.append(transaction)
            logging.debug("Message is a transaction message")
            return "{}{}".format(len(message), message), 2
        else:
            logging.debug("Message is an invalid transaction message [{}]".format(msg_validity[1]))
            return None, -1


"""
Block Miner Function
"""


def find_nonce(difficulty, previous_hash, merkle_tree_root_hash):
    """
    finds nonce for new block
    :param difficulty: difficulty of block to find nonce for
    :type difficulty: int
    :param previous_hash: hash of the previous block
    :type previous_hash: str
    :param merkle_tree_root_hash: hash of the block's transactions merkle tree root
    :type merkle_tree_root_hash: str
    :return: nonce of the block
    :rtype: int
    """
    if not isinstance(difficulty, int):
        raise TypeError("find_nonce: expected nonce to be of type int")
    if not isinstance(previous_hash, str):
        raise TypeError("find_nonce: expected prev_hash to be of type str")
    if not isinstance(merkle_tree_root_hash, str):
        raise TypeError("find_nonce: expected merkle_hash to be of type str")

    nonce = 0

    block_hash = calculate_hash(previous_hash, merkle_tree_root_hash, nonce)
    bin_hash = bin(int(block_hash, 16))[2:].zfill(256)

    while bin_hash[:difficulty] != "0" * difficulty:
        nonce += 1
        block_hash = calculate_hash(previous_hash, merkle_tree_root_hash, nonce)
        bin_hash = bin(int(block_hash, 16))[2:].zfill(256)

        if flags["received new block"]:
            return -1

    return nonce


def mine_new_block(blockchain):
    """
    mining thread target function, creates new block in consensus chain
    :param blockchain: blockchain to append new block to, and to get
    data from
    :type blockchain: Blockchain
    :return: pushes block message into thread_queue if new block found, otherwise doesn't push anything into
    thread_queue
    """
    if not isinstance(blockchain, Blockchain):
        raise TypeError("mine_new_block: expected blockchain to be of type Blockchain")

    public_key = config("public key")

    block_number = blockchain.__len__() + 1

    difficulty_change_count = config("difficulty change count")
    if block_number <= difficulty_change_count:
        difficulty = config("default difficulty")
    else:
        ceiling = difficulty_change_count * math.floor((block_number - 1) / difficulty_change_count)
        floor = ceiling - difficulty_change_count + 1
        delta_t = blockchain.get_block_consensus_chain(ceiling).timestamp() - blockchain.get_block_consensus_chain(
            floor).timestamp
        difficulty = calculate_difficulty(delta_t, blockchain.get_block_consensus_chain(ceiling - 1).difficulty)

    logging.debug("New block's difficulty is {}".format(difficulty))

    if block_number == 1:
        prev_hash = "0" * 64
    else:
        prev_hash = blockchain.get_block_consensus_chain(blockchain.__len__()).self_hash

    block_transactions = []
    all_transactions = transactions.array
    for t in all_transactions:
        overlap = False
        for t2 in block_transactions:
            if t.overlap(t2):
                overlap = True
        if not overlap:
            block_transactions.append(t)
        if len(block_transactions) == 64:
            break
    block_transactions.sort(key=Transaction.sort_key, reverse=True)

    source_transaction = Transaction(int(datetime.datetime.now().timestamp()), [],
                                     [(public_key, config("block reward"))])

    final_block_transactions = [source_transaction] + block_transactions

    merkle_root_hash = calculate_merkle_root_hash(final_block_transactions)

    nonce = find_nonce(difficulty, prev_hash, merkle_root_hash)

    if nonce != -1:
        self_hash = calculate_hash(prev_hash, merkle_root_hash, nonce)
        blockchain.append(block_number, int(datetime.datetime.now().timestamp()), difficulty, nonce, prev_hash,
                          merkle_root_hash, final_block_transactions, self_hash)

        block = blockchain.get_block_consensus_chain(blockchain.__len__())

        message = block.network_format()
        thread_queue.put("{}{}".format(len(message), message))
        flags["created new block"] = True
        logging.info("Created new block")


"""
Main Function
"""


def main():
    global thread_queue
    global flags
    global inputs

    threading.current_thread().name = "MainNodeThread"

    flags["received new block"] = False
    flags["created new block"] = False
    flags["exception"] = False
    flags["finished seeding"] = False

    ip = config("ip address")
    port = config("port")
    seed_ip = config("seed address")
    seed_port = config("seed port")
    sql_address = config("sql address")
    sql_user = config("sql user")
    sql_password = config("sql password")

    blockchain = Blockchain(sql_address, sql_user, sql_password)

    server_socket = initialize_server(ip, port)
    logging.info("Server: Initiated [{}, {}]"
                 .format(server_socket.getsockname()[0], server_socket.getsockname()[1]))

    seeding_thread = threading.Thread(name="Seeding Thread", target=seed_clients, args=(seed_ip, seed_port, port,))
    seeding_thread.start()

    mining_thread = threading.Thread(name="Mining Thread ", target=mine_new_block, args=(blockchain,))
    mining_thread.start()

    inputs.append(server_socket)
    message_queues = {}

    get_most_recent_block = "00047g0000000000000000000000000000000000000000000000000000000000000000000000"

    while inputs:
        readable, writable, exceptional = select.select(inputs.array, client_sockets.array, inputs.array +
                                                        client_sockets.array, 1)

        for sock in readable:
            if sock is server_socket:
                client_socket, address = server_socket.accept()
                inputs.append(client_socket)

                client_socket_exists = False

                for other_sock in client_sockets:
                    if other_sock.getpeername()[0] == address[0]:
                        client_socket_exists = True
                if not client_socket_exists:
                    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    new_socket.connect((address[0], port))
                    client_sockets.append(new_socket)

                    if address[0] not in message_queues:
                        message_queues[address[0]] = queue.Queue()
                    message_queues[address[0]].put(get_most_recent_block)

            else:
                size = sock.recv(5).decode()
                if size:

                    message = sock.recv(int(size, 16)).decode()
                    reply = handle_message(message, blockchain)

                    if reply[1] == -1:
                        logging.debug("No reply")

                    if reply[1] == 1:
                        logging.debug("Replying to sender")
                        if sock.getpeername()[0] not in message_queues:
                            message_queues[sock.getpeername()[0]] = queue.Queue()
                        message_queues[sock.getpeername()[0]].put(reply[0])

                    elif reply[1] == 2:
                        logging.debug("Sending reply to all nodes")

                        for other_sock in client_sockets:
                            if other_sock.getpeername()[0] not in message_queues:
                                message_queues[other_sock.getpeername()[0]] = queue.Queue()
                            message_queues[other_sock.getpeername()[0]].put(reply[0])
                else:
                    address = sock.getpeername()[0]
                    sock.close()
                    inputs.remove(sock)

                    if address in message_queues:
                        del message_queues[address]

                    for other_sock in client_sockets:
                        if other_sock.getpeername()[0] == address:
                            other_sock.close()
                            client_sockets.remove(other_sock)

        for sock in writable:
            address = sock.getpeername()[0]

            if address in message_queues:
                if not message_queues[address].empty():
                    message = message_queues[address].get()
                    sock.send(message.encode())

        for sock in exceptional:
            address = sock.getpeername()[0]
            for other_sock in client_sockets:
                if other_sock.getpeername()[0] == address:
                    other_sock.close()
                    client_sockets.remove(other_sock)
            for other_sock in inputs:
                if other_sock.getpeername()[0] == address:
                    other_sock.close()
                    inputs.remove(other_sock)

            if address in message_queues:
                del message_queues[address]

        if flags["received new block"]:
            pass

        if flags["created new block"]:
            flags["created new block"] = False

            mining_thread.join()
            if not thread_queue.empty():
                message = thread_queue.get()
                logging.debug("Sending new block to all nodes")

                for sock in client_sockets:
                    if sock.getpeername()[0] not in message_queues:
                        message_queues[sock.getpeername()[0]] = queue.Queue()
                    message_queues[sock.getpeername()[0]].put(message)

            mining_thread = threading.Thread(name="Mining Thread ", target=mine_new_block, args=(blockchain,))
            mining_thread.start()

        if flags["finished seeding"]:
            pass

        if flags["exception"]:
            pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
