"""
Author: Oren Sitton
File: Full Node.py
Python Version: 3.8
Description:
"""
import socket
import select
import logging
import threading
from time import sleep

from Classes.SyncedArray import SyncedArray
from Classes.Blockchain import Blockchain

client_sockets = SyncedArray(name="client list")


def initiate_server(ip, port):
    """
    initializes server socket object to address,
    non-blocking and to accept new connections
    :param ip: ipv4 address
    :type ip: str
    :param port: tcp port
    :type port: int
    :return: server socket
    :rtype: socket.socket
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setblocking(False)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    return server_socket


def initiate_client(ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
        logging.info("Connected to node [{}, {}]"
                     .format(client_socket.getpeername()[0], client_socket.getpeername()[1]))

    except ConnectionRefusedError:
        logging.info("Connection attempt refused by node [{}, {}]"
                     .format(ip, port))

    else:
        client_sockets.append(client_socket)


def initiate_clients(addresses, port):
    threads = []
    for i, address in enumerate(addresses):
        thread = threading.Thread(name="client connection attempt {}".format(i+1), target=initiate_client, args=(address, port, ))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    logging.info("{} nodes accepted connection"
                 .format(len(client_sockets)))



def peer_seed(ip, port, **kwargs):
    if kwargs.get("attempts"):
        attempts = kwargs.get("attempts")
    else:
        attempts = 5

    if kwargs.get("delay"):
        delay = kwargs.get("delay")
    else:
        delay = 5

    seed_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    seed_client.connect((ip, port))

    for x in range(attempts):
        seed_client.send("0014GetAddresses\r\n".encode())
        data = seed_client.recv(4).decode()
        data = seed_client.recv(int(data)).decode()
        data = data.split("\r\n")

        if data[0] == "Addresses" and len(data) > 2:
            seed_client.close()
            return data[1:-1]

        else:
            sleep(delay)

    seed_client.close()
    return []


def main():
    # open configuration file
    ip = "localhost"
    port = 8334
    seed_ip = "localhost"
    seed_port = 8333

    # initialize blockchain & transactions list

    # initiate server socket
    server_socket = initiate_server(ip, port)
    logging.info("Server initiated [{}, {}]"
                 .format(server_socket.getsockname()[0], server_socket.getsockname()[1]))

    # initiate inputs list (from config file or from seed server)
    peer_addresses = peer_seed(seed_ip, seed_port, attempts=1)
    logging.info("Seeding yielded {} addresses".format(len(peer_addresses)))

    # initiate clients
    threading.Thread(name="client connection attempts", target=initiate_clients,args=(peer_addresses, port, )).start()
    del peer_addresses

    # main loop

    inputs = [server_socket]
    outputs = []
    message_queue = {}

    while inputs:
        readable, writable, exceptional = select.select(inputs + client_sockets.array, outputs, inputs)

        for sock in readable:
            if sock is server_socket:
                connection, client_address = server_socket.accept()
                connection.setblocking(False)

                inputs.append(connection)



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s, %(asctime)s: %(message)s")
    main()
