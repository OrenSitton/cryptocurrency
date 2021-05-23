"""
Author: Oren Sitton
File: BlockTest.py
Python Version: 3
Description: 
"""
from Dependencies.full_node import handle_message_block
from Dependencies import Blockchain
import logging

def main():
    bc = Blockchain()
    print(handle_message_block("d000001609bb8271400000000000000000000000000000000000000000000000000000000000e99b5000000000000000000000000000000000000000000000000000000000000000047a654f8b81a510ccac172063275a3005be51f33c2cb52caffa666013f372c150100153e609bb81e0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a", bc))
    pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
