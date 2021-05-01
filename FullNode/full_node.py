"""
Author: Oren Sitton
File: Full Node.py
Python Version: 3
Description:
"""
import datetime
# TODO: update protocol for bigger nonce
# TODO: update protocol for csv synchronizing
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

from Dependencies import Blockchain
from Dependencies import Block
from Dependencies import Flags
from Dependencies import SyncedArray
from Dependencies import Transaction

"""
Global Variables
----------------
inputs : SyncedArray
    list of current nodes connected to node's server socket
client_sockets : SyncedArray
    list of current client sockets connected to other node's server sockets
transactions : SyncedArray
    list of pending transactions
thread_queue : queue.SimpleQueue
    queue to load return value from mining thread
flags : Flags
    flags object to coordinate between threads
"""

inputs = SyncedArray(name="input list")
client_sockets = SyncedArray(name="client List")
transactions = SyncedArray(name="transaction List")
thread_queue = queue.SimpleQueue()
flags = Flags()

"""
Initiation Functions
--------------------
"""


def get_config_data(key, directory="Dependencies\\config.txt"):
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
    try:
        with open(directory, "rb") as file:
            configuration = pickle.load(file)
    except FileNotFoundError:
        raise FileNotFoundError("get_config_data: configuration file not found at {}".format(directory))
    else:
        if not isinstance(configuration, dict):
            raise TypeError("get_config_data: unpickled object is not a dictionary")
        else:
            return configuration.get(key)


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
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setblocking(False)
        server_socket.bind((ip, port))
        server_socket.listen(5)
    except OSError:
        return None
    else:
        return server_socket


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
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
        logging.info("[{}, {}]: Connected to node"
                     .format(client_socket.getpeername()[0], client_socket.getpeername()[1]))

    except ConnectionRefusedError:
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
    threads = []
    for i, address in enumerate(addresses):
        if address != get_config_data("ip_address"):
            thread = threading.Thread(name="Client Connection Thread {}".format(i + 1), target=initialize_client,
                                      args=(address, port,))
            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()

    logging.info("{} nodes accepted connection"
                 .format(len(client_sockets)))


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
    if kwargs.get("attempts"):
        attempts = kwargs.get("attempts")
    else:
        attempts = 5

    if kwargs.get("delay"):
        delay = kwargs.get("delay")
    else:
        delay = 5

    peer_addresses = []

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
---------------------
"""


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


def validate_transaction_format(transaction):
    """
    validates that the transaction's format is valid
    :param transaction: transaction to validate
    :type transaction: Transaction
    :return: True if the transaction is valid, False if else
    :rtype: bool
    """
    # validate that transaction inputs are in order
    for x in range(0, len(transaction.inputs) - 1):
        if int(transaction.inputs[x][0], 16) > int(transaction.inputs[x + 1][0], 16):
            return False, "inputs order invalid"
        elif int(transaction.inputs[x][0], 16) == int(transaction.inputs[x+1][0], 16):
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


def validate_transaction_data(transaction, blockchain, previous_block_hash):
    """

    :param transaction:
    :type transaction: Transaction
    :param blockchain:
    :type blockchain:
    :param previous_block_hash:
    :type previous_block_hash:
    :return:
    :rtype:
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

    :param transaction:
    :type transaction: Transaction
    :param blockchain:
    :type blockchain:
    :return:
    :rtype:
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


def validate_transaction(transaction, blockchain, previous_block_hash=""):
    if validate_transaction_format(transaction)[0]:
        if previous_block_hash:
            return validate_transaction_data(transaction, blockchain, previous_block_hash)
        else:
            return validate_transaction_data_consensus(transaction, blockchain)
    return validate_transaction_format(transaction)



def calculate_difficulty(delta_t, prev_difficulty):
    ratio = (1209600 / delta_t)
    difficulty_addition = math.log(ratio, 2)
    if difficulty_addition > 0:
        return prev_difficulty + math.ceil(difficulty_addition)
    elif difficulty_addition < 0 < prev_difficulty + math.floor(difficulty_addition):
        return prev_difficulty + math.floor(difficulty_addition)
    elif difficulty_addition < 0:
        return 1
    return prev_difficulty


def calculate_hash(merkle_root_hash, prev_block_hash, nonce):
    value = "{}{}{}".format(prev_block_hash, merkle_root_hash, nonce)
    return sha256(value.encode()).hexdigest()


def calculate_merkle_root_hash(block_transactions):
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


"""
Build Message Functions
-------------------------
"""


def build_peers_message(peers_list):
    message = "b{}".format(hexify(len(peers_list), 2))
    for address in peers_list:
        address_bytes = address.split(".")
        for byte in address_bytes:
            message += hexify(int(byte), 2)
    return message


def build_error_message(error_message):
    message = "f{}".format(hexify_string(error_message))
    return message


"""
Handle Message Functions
--------------------------
"""


def handle_peer_request_message():
    logging.debug("Message is a peer request message")
    reply = build_peers_message(inputs.array)
    reply = "{}{}".format(hexify(len(reply), 5), reply)
    return reply, 1


def handle_peer_message(message):
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


def handle_block_request_message(message, blockchain):
    if len(message) != 71:
        # message not in correct format
        logging.debug("Message is an invalid block request")
        return None, -1
    else:
        block_number = int(message[1:7], 16)
        previous_block_hash = message[7:]
        block = ""
        if block_number == 0 and previous_block_hash.replace("0", ""):
            # message in incorrect format
            logging.debug("Message is an invalid block request")
            return None, -1
        elif block_number == 0:
            block = blockchain.get_block_consensus_chain(blockchain.__len__())
        else:
            # return requested block if have, else return nothing
            block = blockchain.get_block_by_previous_hash(previous_block_hash)

        if block:
            reply = block.network_format()
            logging.debug("Message is a block request")
            return "{}{}".format(hexify(len(reply), 5), reply), 1
        else:
            logging.debug("Message is an invalid block request")
            return None, -1


def handle_block_message(message, blockchain):
    # TODO: update to match new protocol
    # validate minimum length
    try:
        block = Block.from_network_format(message)
    except ValueError:
        return None, -1

    # check if block already received
    if blockchain.get_block_by_hash(block.self_hash):
        return None, -1

    # check if previous block exists
    previous_block = blockchain.get_block_by_hash(block.prev_hash)
    if not previous_block:
        return None, -1

    # check if block number relevant
    if block.block_number < blockchain.__len__() - 1:
        return None, -1

    # validate time created
    if block.timestamp <= previous_block.timestamp:
        return None, -1

    # validate difficulty
    if block.block_number <= 2016:
        if block.difficulty != get_config_data("default difficulty"):
            return None, -1
    else:
        maximum_block = blockchain.get_block_by_hash(block.prev_hash)
        while maximum_block.block_number % 2016 != 0:
            maximum_block = blockchain.get_block_by_hash(maximum_block.prev_hash)
        minimum_block = blockchain.get_block_by_hash(maximum_block.prev_hash)
        while minimum_block.block_number % 2016 != 0:
            minimum_block = blockchain.get_block_by_hash(minimum_block.prev_hash)
        delta_t = maximum_block.timestamp - minimum_block.timestamp
        if block.difficulty != calculate_difficulty(delta_t, blockchain.get_block_by_previous_hash(minimum_block.self_hash)):
            return None, -1

    # validate nonce #
    maximum = 2 ** (256 - block.difficulty)
    b_hash = calculate_hash(block.merkle_root_hash, block.prev_hash, block.nonce)
    int_hash = int(b_hash, 16)

    if int_hash > maximum:
        return None, -1

    # validate first transaction
    if len(block.transactions[0].inputs):
        return None, -1
    elif len(block.transactions[0].outputs) != 1:
        return None, -1
    elif block.transactions[0].outputs[0][1] != get_config_data("block reward"):
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
    blockchain.append_block(block)

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
    # TODO: return alternative message for futuristic block
    return "{}{}".format(len(block.network_format()), block.network_format())


def handle_transaction_message(message, blockchain):
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


def handle_error_message(message):
    logging.debug("Message is an error message [{}]".format(message))
    return None, -1


def handle_message(message, blockchain):
    message_handling_functions = dict(a=lambda: handle_peer_request_message(),
                                      b=lambda: handle_peer_message(message),
                                      c=lambda: handle_block_request_message(message, blockchain),
                                      d=lambda: handle_block_message(message, blockchain),
                                      e=lambda: handle_transaction_message(message, blockchain),
                                      f=lambda: handle_error_message(message))

    message_type = message[:1]

    if message_type not in message_handling_functions:
        logging.debug("Message is invalid (unrecognized message type)")
        reply = build_error_message("unrecognized message type")
        reply = "{}{}".format(hexify(len(reply), 5), reply)
        return reply, 1
    else:
        return message_handling_functions[message_type]()


"""
Block Miner Function
--------------------
"""


def find_nonce(difficulty, prev_hash, merkle_hash):
    """
    finds nonce for new block
    :param difficulty:
    :type difficulty:
    :param prev_hash:
    :type prev_hash:
    :param merkle_hash:
    :type merkle_hash:
    :return:
    :rtype:
    """
    nonce = 0

    block_hash = calculate_hash(merkle_hash, prev_hash, nonce)
    bin_hash = bin(int(block_hash, 16))[2:].zfill(256)

    while bin_hash[:difficulty] != "0" * difficulty:
        nonce += 1
        block_hash = calculate_hash(merkle_hash, prev_hash, nonce)
        bin_hash = bin(int(block_hash, 16))[2:].zfill(256)

        if flags["received new block"]:
            return -1

    return nonce


def mine_new_block(blockchain):
    public_key = get_config_data("public key")
    block_number = blockchain.__len__() + 1

    difficulty = 0

    if block_number <= 2016:
        difficulty = get_config_data("default difficulty")
    else:
        ceiling = 2016 * math.floor((block_number - 1) / 2016)
        floor = ceiling - 2015
        delta_t = blockchain.get_block_consensus_chain(ceiling)[2] - blockchain.get_block_consensus_chain(floor)[2]
        difficulty = calculate_difficulty(delta_t, int(blockchain.get_block_consensus_chain(ceiling - 1)[4]))

    logging.debug("New block's difficulty is {}".format(difficulty))

    prev_hash = ""

    if block_number == 1:
        prev_hash = "0" * 64
    else:
        prev_hash = blockchain.get_block_consensus_chain(blockchain.__len__())[8]

    block_transactions = []
    all_transactions = transactions.array
    for t in all_transactions:
        invalid_transaction = False
        for t2 in block_transactions:
            if t.overlap(t2):
                invalid_transaction = True
        if not invalid_transaction:
            block_transactions.append(t)
        if len(block_transactions) == 64:
            break
    block_transactions.sort(key=Transaction.sort_key, reverse=True)

    source_transaction = Transaction(int(datetime.datetime.now().timestamp()), [], [(public_key, 10)])

    final_block_transactions = [source_transaction]
    for t in block_transactions:
        final_block_transactions.append(t)

    merkle_root_hash = calculate_merkle_root_hash(final_block_transactions)

    nonce = find_nonce(difficulty, prev_hash, merkle_root_hash)

    if nonce == -1:
        return

    blockchain.append(block_number, int(datetime.datetime.now().timestamp()), prev_hash, difficulty, nonce,
                      merkle_root_hash, final_block_transactions, calculate_hash(merkle_root_hash, prev_hash, nonce))
    block = blockchain.get_block_consensus_chain(blockchain.__len__())

    message = build_block_message(block)
    thread_queue.put(("{}{}".format(len(message), message), 2))
    flags["created new block"] = True
    logging.info("Created new block")


"""
Main Function
-------------
"""


def main():
    global thread_queue
    global flags
    global inputs
    global outputs

    threading.current_thread().name = "MainNodeThread"

    flags["received new block"] = False
    flags["created new block"] = False
    flags["exception"] = False
    flags["finished seeding"] = False
    ip = get_config_data("ip address")
    port = get_config_data("port")
    seed_ip = get_config_data("seed address")
    seed_port = get_config_data("seed port")
    sql_address = get_config_data("sql address")
    sql_user = get_config_data("sql user")
    sql_password = get_config_data("sql password")
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

    synchronized = False
    readable, writable, exceptional = select.select(client_sockets + inputs, outputs, client_sockets + inputs, 1)
    request_newest_block_message = hexify(71, 5) + "c" + "0" * 70

    if not writable:
        synchronized = True

    for sock in writable:
        sock.send(request_newest_block_message)

    sync_message_queues = {}
    target_block_number = 0
    current_block_number = blockchain.__len__()

    while inputs:
        # TODO: set up loop for sync messages
        readable, writable, exceptional = select.select(inputs.array, client_sockets.array, inputs.array +
                                                        client_sockets.array, 0)

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
            else:
                size = sock.recv(5).decode()
                if size:
                    message = sock.recv(int(size)).deocde()
                    reply = handle_message(message)

                    if reply[1] == -1:
                        logging.debug("No reply")

                    if reply[1] == 1:
                        logging.debug("Replying to sender")
                        if sock.getpeername()[0] not in message_queues:
                            message_queues[sock.getpeername()[0]] = queue.SimpleQueue()
                        message_queues[sock.getpeername()[0]].put(reply[0])

                    elif reply[1] == 2:
                        logging.debug("Sending reply to all nodes")

                        for other_sock in client_sockets:
                            if other_sock.getpeername()[0] not in message_queues:
                                message_queues[other_sock.getpeername()[0]] = queue.SimpleQueue()
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

    while inputs:
        readable, writable, exceptional = select.select(inputs.array, client_sockets.array, inputs.array +
                                                        client_sockets.array, 0)

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
            else:
                size = sock.recv(5).decode()
                if size:
                    message = sock.recv(int(size)).deocde()
                    reply = handle_message(message)

                    if reply[1] == -1:
                        logging.debug("No reply")

                    if reply[1] == 1:
                        logging.debug("Replying to sender")
                        if sock.getpeername()[0] not in message_queues:
                            message_queues[sock.getpeername()[0]] = queue.SimpleQueue()
                        message_queues[sock.getpeername()[0]].put(reply[0])

                    elif reply[1] == 2:
                        logging.debug("Sending reply to all nodes")

                        for other_sock in client_sockets:
                            if other_sock.getpeername()[0] not in message_queues:
                                message_queues[other_sock.getpeername()[0]] = queue.SimpleQueue()
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
            pass
        if flags["finished seeding"]:
            flags["finished seeding"] = False
            seeding_thread.join()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
