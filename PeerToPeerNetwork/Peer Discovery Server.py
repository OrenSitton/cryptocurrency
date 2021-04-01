"""
Author: Oren Sitton
File: Peer Discovery Server.py
Python Version: 3.8
Description: Server used by nodes to discover other nodes in the network (peer discovery)
"""
import socket
import select
import logging
import sys


def initialize_server(ip, port):
    """
    initializes server socket object to address,
    non-blocking and to accept new connections
    :param ip: ipv4 address
    :type ip: str
    :param port: tcp port
    :type port: int
    :return: initialized server socket
    :rtype: socket.socket
    """

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setblocking(False)
    server.bind((ip, port))
    server.listen(5)

    logging.info("Server initiated at address ({}, {})"
                 .format(server.getsockname()[0], server.getsockname()[1]))

    return server


def handle_message(request, ip_addresses, destination):
    """
    handles incoming messages from clients. Analyzes client request and creates appropriate response.
    :param request: message received from client
    :type request: str
    :param ip_addresses: current stored addresses of nodes in the network
    :type ip_addresses: list
    :param destination: address of the client who sent the request
    :type destination: str
    :return: reply to send to client
    :rtype: str
    """

    if request == "GetAddresses\r\n":
        if destination in ip_addresses and ip_addresses[len(ip_addresses) - 1] != destination:
            ip_addresses[ip_addresses.index(destination)] = ip_addresses[len(ip_addresses) - 1]
            # replace requester's address with a different address

        reply = "Addresses\r\n"

        for x in range(len(ip_addresses) - 1):
            if ip_addresses[x] != "":
                reply += ip_addresses[x] + "\r\n"

    else:
        reply = "Error\r\nunrecognized request\r\n"

    length = len(reply.encode('utf-8'))
    prefix = "0" * (4-len(str(length)))

    reply = "{}{}{}".format(prefix, str(length), reply)

    return reply


def main():
    # open config file
    ip = "localhost"
    port = 8333
    addresses_amount = 3
    ip_addresses = []
    count = 0
    for x in range(addresses_amount + 1):
        ip_addresses.append("")

    # initiate server socket
    server_socket = initialize_server(ip, port)

    # main loop

    inputs = [server_socket]
    outputs = []
    message_queues = {}

    while inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for sock in readable:
            if sock is server_socket:
                connection, client_address = server_socket.accept()
                connection.setblocking(False)
                inputs.append(connection)

                logging.info("Connected to client at ({}, {})"
                             .format(client_address[0], client_address[1]))

                if client_address[0] not in ip_addresses:
                    ip_addresses[count] = client_address[0]
                    count += 1
                    count %= addresses_amount + 1

            else:
                try:
                    data = sock.recv(4).decode()
                    if data:
                        logging.info("Received message from client at ({}, {})"
                                     .format(sock.getpeername()[0], sock.getpeername()[1]))
                        data = sock.recv(int(data)).decode()
                        if sock in message_queues:
                            message_queues[sock] = message_queues[sock] + [data]
                        else:
                            message_queues[sock] = [data]

                        if sock not in outputs:
                            outputs.append(sock)

                    else:
                        logging.info("Disconnected from client at ({}, {})"
                                     .format(sock.getpeername()[0], sock.getpeername()[1]))

                        if sock in outputs:
                            outputs.remove(sock)
                        inputs.remove(sock)
                        sock.close()
                        if sock in message_queues:
                            del message_queues[sock]

                except ConnectionResetError:
                    logging.info("An existing connection was forcibly closed by the client: ({}, {})"
                                 .format(sock.getpeername()[0], sock.getpeername()[1]))

                    if sock in outputs:
                        outputs.remove(sock)
                    inputs.remove(sock)
                    sock.close()
                    if sock in message_queues:
                        del message_queues[sock]

        for sock in writable:
            if sock in message_queues:
                messages = message_queues[sock]
                next_msg = messages[0]
                messages.remove(next_msg)
                message_queues[sock] = messages
                if len(messages) == 0:
                    del message_queues[sock]
                    outputs.remove(sock)

                reply = handle_message(next_msg, ip_addresses, sock.getpeername()[0])
                sock.send(reply.encode())
                logging.info("Sent message to client at ({}, {})"
                             .format(sock.getpeername()[0], sock.getpeername()[1]))

        for sock in exceptional:
            inputs.remove(sock)
            if sock in outputs:
                outputs.remove(sock)
            sock.close()
            del message_queues[sock]
            logging.info("Disconnected from client at ({}, {})"
                         .format(sock.getpeername()[0], sock.getpeername()[1]))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(asctime)s: %(message)s")
    main()
