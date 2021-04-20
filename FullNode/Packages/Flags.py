"""
Author: Oren Sitton
File: SyncedDictionary.py
Python Version: 3.8
Description: 
"""
import logging
from threading import Semaphore, Lock


class Flags:
    """
    Flags class, implements flags that can be used across multiple threads simultaneously

    Attributes
    ----------
    __dictionary : dict
        a list containing the instances data
    name : str
        the name of the list (default "list")
    max_readers : int
        the maximum amount of simultaneous readers per instance (default 2)
    semaphore_lock : Semaphore
        a semaphore lock used to limit reading privileges
    write_lock : Lock
        a lock used to limit writing privileges

    Methods
    -------
    __init__(name="dictionary")
        initializes the list and locks
    acquire_edit_permissions(acquired=0)
        acquires the write lock and read locks
    release_edit_permissions(released=0)
        releases the write and read locks
    remove(key)
        removes the value from the dictionary
    __len__()
        returns the length of the dictionary
    __str__()
        returns the dictionary as a string
    __getitem__(key)
        returns the value of the key
    __setitem__(key, value)
        sets the value of the key to the value in the dictionary
    dictionary()
        returns a copy of the dictionary, as a python list
    """

    def __init__(self, name="flags", max_readers=2):
        self.__flags = {}
        self.name = name
        self.max_readers = max_readers
        self.semaphore_lock = Semaphore(value=self.max_readers)
        self.write_lock = Lock()

    def acquire_edit_permissions(self, acquired=0):
        for x in range(self.max_readers - acquired):
            self.semaphore_lock.acquire()
        logging.debug("Acquired reading locks for {}".format(self.name))

        self.write_lock.acquire()
        logging.debug("Acquired write lock for {}".format(self.name))

    def release_edit_permissions(self, released=0):
        for x in range(self.max_readers - released):
            self.semaphore_lock.release()
        logging.debug("Released reading locks for {}".format(self.name))

        self.write_lock.release()
        logging.debug("Released writing locks for {}".format(self.name))

    def acquire_read_permissions(self):
        self.semaphore_lock.acquire()
        logging.debug("Acquired read lock for {}".format(self.name))

    def release_read_permissions(self):
        self.semaphore_lock.release()
        logging.debug("Released read lock for {}".format(self.name))

    def set_flag(self, flag, value):
        self.__flags[flag] = value

    def __str__(self):
        self.semaphore_lock.acquire()
        string_representation = self.__flags.__str__()
        self.semaphore_lock.release()

        return string_representation


def main():
    pass


if __name__ == '__main__':
    main()
