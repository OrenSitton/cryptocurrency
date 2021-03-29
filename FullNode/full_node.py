"""
Author: Oren Sitton
File: Full Node.py
Python Version: 3.8
Description:
"""
import socket
import select
import logging
from time import sleep
import threading


def open_configuration():
    pass


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
    client_addresses = []

    # initialize blockchain & transactions list

    # initiate server socket
    server = initiate_server(ip, port)
    logging.info("Server initiated [{}, {}]"
                 .format(server.getsockname()[0], server.getsockname()[1]))

    # initiate inputs list (from config file or from seed server)
    peer_addresses = peer_seed(seed_ip, seed_port, attempts=1)
    logging.info("Seeding yielded {} addresses".format(len(peer_addresses)))

    client_addresses += peer_addresses

    # initiate clients
    clients = []

    for address in client_addresses:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.append(client)
        try:
            client.connect((address, 8334))
            logging.info("Connected to node [{}, {}]"
                         .format(client.getpeername()[0], client.getpeername()[1]))
        except ConnectionRefusedError:
            logging.info("Connection attempt to node refused [{}, {}]"
                         .format(address, port))
            clients.remove(client)
            client_addresses.remove(address)

    logging.info("{} nodes accepted connection"
                 .format(len(clients)))

    # main loop

    inputs = []
    outputs = []
    message_queue = {}


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(asctime)s: %(message)s")
    main()
