"""
Author: Oren Sitton
File: __init__.py
Python Version: 3
"""
import logging

try:
    from Dependencies.Blockchain import Blockchain
    from Dependencies.Block import Block
    from Dependencies.SyncedArray import SyncedArray
    from Dependencies.Transaction import Transaction
    from Dependencies.SyncedDictionary import SyncedDictionary

    from Dependencies.methods import *

except ModuleNotFoundError:
    try:
        from Blockchain import Blockchain
        from Block import Block
        from SyncedArray import SyncedArray
        from Transaction import Transaction
        from SyncedDictionary import SyncedDictionary

        from methods import *

    except ModuleNotFoundError:
        logging.critical("Could not find dependencies")
        exit(-1)
