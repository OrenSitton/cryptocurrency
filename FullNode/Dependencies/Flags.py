"""
Author: Oren Sitton
File: SyncedDictionary.py
Python Version: 3
"""
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
    __getitem__(flag)
        returns the value of flags[flag]
     __setitem__(flag, value)
        sets the flag to value
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
    """

    def __init__(self, name="flags", max_readers=2):
        """
        initializer for flags objects
        :param name: name of the object (to be shown in logging messages)
        :type name: str
        :param max_readers: maximum amount of simultaneous readers
        :type max_readers: int
        """
        if not isinstance(name, str):
            raise TypeError("Flags.__init__: expected name to be of type str")
        if not isinstance(max_readers, int):
            raise TypeError("Flags.__init__: expected max_readers to be of type int")

        self.__flags = {}
        self.name = name
        self.max_readers = max_readers
        self.semaphore_lock = Semaphore(value=self.max_readers)
        self.write_lock = Lock()

    def __getitem__(self, flag):
        """
        returns the value of flags[flag]
        :param flag: flag to return item for
        :type flag: Any
        :return: flags[flag]
        :rtype: Any
        """
        self.semaphore_lock.acquire()
        item = self.__flags.get(flag)
        self.semaphore_lock.release()
        return item

    def __setitem__(self, flag, value):
        self.acquire_edit_permissions()
        self.__flags[flag] = value
        self.release_edit_permissions()

    def __str__(self):
        """
        returns string version of the flags
        :return: string representation of the flags
        :rtype: str
        """
        self.semaphore_lock.acquire()
        string_representation = "Flag : Value\n------------\n\n"
        for key, value in self.__flags.items():
            string_representation += "{} : {}\n".format(key, value)
        self.semaphore_lock.release()

        return string_representation

    def acquire_edit_permissions(self, acquired=0):
        if not isinstance(acquired, int):
            raise TypeError("Flags.acquire_edit_permissions: expected acquired to be of type int")
        if acquired > self.max_readers:
            raise ValueError("Flags.acquire_edit_permission: expected acquired to be less than max_readers")

        for x in range(self.max_readers - acquired):
            self.semaphore_lock.acquire()
        self.write_lock.acquire()

    def release_edit_permissions(self, released=0):
        if not isinstance(released, int):
            raise TypeError("Flags.release_edit_permissions: expected released to be of type int")
        if released > self.max_readers:
            raise ValueError("Flags.release_edit_permission: expected released to be less than max_readers")

        for x in range(self.max_readers - released):
            self.semaphore_lock.release()

        self.write_lock.release()


def main():
    pass


if __name__ == '__main__':
    main()
