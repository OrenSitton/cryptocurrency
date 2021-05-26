"""
Author: Oren Sitton
File: SyncedDictionary.py
Python Version: 3
"""
from threading import Semaphore, Lock


class SyncedDictionary:
    """
    SyncedDictionary class, implements SyncedDictionary that can be used across multiple threads simultaneously

    Attributes
    ----------
    __SyncedDictionary : dict
        a dictionary containing the SyncedDictionary
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
    __getitem__(flag)
        returns the value of SyncedDictionary[flag]
     __setitem__(flag, value)
        sets the flag to value
    __str__()
        returns the dictionary as a string
    acquire_edit_permissions(acquired=0)
        acquires the write lock and read locks
    release_edit_permissions(released=0)
        releases the write and read locks
    """

    def __init__(self, max_readers=2):
        """
        initializer for SyncedDictionary objects
        :param max_readers: maximum amount of simultaneous readers (default 2)
        :type max_readers: int
        """
        if not isinstance(max_readers, int):
            raise TypeError("SyncedDictionary.__init__: expected max_readers to be of type int")

        self.__dict = {}
        self.max_readers = max_readers
        self.semaphore_lock = Semaphore(value=self.max_readers)
        self.write_lock = Lock()

    def __getitem__(self, key):
        """
        returns the value of SyncedDictionary[flag]
        :param key: flag to return item for
        :type key: Any
        :return: SyncedDictionary[flag]
        :rtype: Any
        """
        self.semaphore_lock.acquire()
        item = self.__dict.get(key)
        self.semaphore_lock.release()
        return item

    def __setitem__(self, key, value):
        self.acquire_edit_permissions()
        self.__dict[key] = value
        self.release_edit_permissions()

    def __str__(self):
        """
        returns string version of the SyncedDictionary
        :return: string representation of the SyncedDictionary
        :rtype: str
        """
        self.semaphore_lock.acquire()
        string_representation = ""
        for key, value in self.__dict.items():
            string_representation += "{}: {}, ".format(key, value)
        string_representation = "{" + string_representation[:-1] + "}"
        self.semaphore_lock.release()

        return string_representation

    def acquire_edit_permissions(self, acquired=0):
        if not isinstance(acquired, int):
            raise TypeError("SyncedDictionary.acquire_edit_permissions: expected acquired to be of type int")
        if acquired > self.max_readers:
            raise ValueError("SyncedDictionary.acquire_edit_permission: expected acquired to be less than max_readers")

        for x in range(self.max_readers - acquired):
            self.semaphore_lock.acquire()
        self.write_lock.acquire()

    def release_edit_permissions(self, released=0):
        if not isinstance(released, int):
            raise TypeError("SyncedDictionary.release_edit_permissions: expected released to be of type int")
        if released > self.max_readers:
            raise ValueError("SyncedDictionary.release_edit_permission: expected released to be less than max_readers")

        for x in range(self.max_readers - released):
            self.semaphore_lock.release()

        self.write_lock.release()


def main():
    pass


if __name__ == '__main__':
    main()
