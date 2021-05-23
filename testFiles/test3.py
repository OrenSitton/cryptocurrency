"""
Author: Oren Sitton
File: test3.py
Python Version: 3
Description: 
"""



def main():
    server_socket = socket.socket()
    server_socket.bind(("localhost", 10000))
    server_socket.listen(5)
    print(server_socket.accept())
    print(server_socket.accept())


if __name__ == '__main__':
    main()
