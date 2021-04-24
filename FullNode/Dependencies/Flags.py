"""
Author: Oren Sitton
File: SyncedDictionary.py
Python Version: 3
"""
import logging
from threading import Semaphore, Lock


class Flags:
    """
    Flags class, implements flags that can be used across multiple threads simultaneously

    Attributes
    ----------
    __flags : dict
        a dictionary containing the flags
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
    __str__()
        returns the dictionary as a string
    acquire_edit_permissions(acquired=0)
        acquires the write lock and read locks
    acquire_read_permissions()
        acquires read lock
    release_edit_permissions(released=0)
        releases the write and read locks
    release_read_permissions()
        releases read lock
    set_flag(flag, value)
        sets the flag to value
    """

    def __init__(self, name="flags", max_readers=2):
        """
        initializer for flags objects
        :param name: name of the object (to be shown in logging messages)
        :type name: str
        :param max_readers: maximum amount of simultaneous readers
        :type max_readers: int
        """
        self.__flags = {}
        self.name = name
        self.max_readers = max_readers
        self.semaphore_lock = Semaphore(value=self.max_readers)
        self.write_lock = Lock()

    def __str__(self):
        """
        returns string version of the flags
        :return: string representation of the flags
        :rtype: str
        """
        self.acquire_read_permissions()
        string_representation = "Flag : Value\n------------\n\n"
        for key, value in self.__flags.items():
            string_representation += "{} : {}\n".format(key, value)
        self.release_read_permissions()

        return string_representation

    def acquire_edit_permissions(self, acquired=0):
        for x in range(self.max_readers - acquired):
            self.semaphore_lock.acquire()
        logging.debug("Acquired reading locks for {}".format(self.name))

        self.write_lock.acquire()
        logging.debug("Acquired write lock for {}".format(self.name))

    def acquire_read_permissions(self):
        self.semaphore_lock.acquire()
        logging.debug("Acquired read lock for {}".format(self.name))

    def release_edit_permissions(self, released=0):
        for x in range(self.max_readers - released):
            self.semaphore_lock.release()
        logging.debug("Released reading locks for {}".format(self.name))

        self.write_lock.release()
        logging.debug("Released writing locks for {}".format(self.name))

    def release_read_permissions(self):
        self.semaphore_lock.release()
        logging.debug("Released read lock for {}".format(self.name))

    def set_flag(self, flag, value):
        self.acquire_edit_permissions()
        self.__flags[flag] = value
        self.release_edit_permissions()


def main():
    pass


if __name__ == '__main__':
    main()
