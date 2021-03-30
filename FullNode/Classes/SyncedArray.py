"""
Author: Oren Sitton
File: synced_array.py
Python Version: 3.8
Description: 
"""
import threading
import logging


class SyncedArray:
    """
    SyncedArray class, implements an array that can be used across multiple threads simultaneously

    Attributes
    ----------
    array : list
        a list containing the instances data
    name : str
        the name of the list (default "list")
    max_readers : int
        the maximum amount of simultaneous readers per instance
    semaphore_lock : Semaphore
        a semaphore lock used to limit reading privileges
    write_lock : Lock
        a lock used to limit writing privileges

    Methods
    -------
    __init__(name="list")
        initializes the list and locks
    acquire_edit_permissions()
        acquires the write lock and read locks
    release_edit_permissions()
        releases the write and read locks
    append(value)
        appends the value to the end of the array
    remove(value)
        removes the value from the array
    __len__()
        returns the length of the array
    __str__()
        returns the array as a string
    __getitem__(index)
        returns the item at the index(th) place in the array
    __setitem__(index, value)
        sets the value of the item at the index(th) place in the array to value
    array()
        returns a copy of the array, as a python list
    """

    def __init__(self, name="list", max_readers=2):
        """
        initializes the list and locks
        :param name: name of the list (to be shown in log messages)
        :type name: str
        :param max_readers: the maximum amount of simultaneous readers
        :type max_readers: int
        """
        self.__array = []
        self.name = name
        self.max_readers = max_readers
        self.semaphore_lock = threading.Semaphore(value=self.max_readers)
        self.write_lock = threading.Lock()

    def acquire_edit_permissions(self, acquired=0):
        """
        acquires the write lock and read locks
        :param acquired: amount of semaphore locks already acquired by caller
        :type acquired: int
        """
        self.write_lock.acquire()
        logging.debug("Acquired write lock for {}".format(self.name))

        for x in range(self.max_readers - acquired):
            self.semaphore_lock.acquire()

        logging.debug("Acquired all reading locks for {}".format(self.name))

    def release_edit_permissions(self, released=0):
        """
        releases the write and read locks
        :param released: amount of semaphore locks already released by caller
        :type released: int
        """
        self.write_lock.release()
        logging.debug("Released write lock for {}".format(self.name))

        for x in range(self.max_readers - released):
            self.semaphore_lock.release()
        logging.debug("Released all reading locks for {}".format(self.name))

    def append(self, value):
        """
        appends the value to the end of the array
        :param value: value to append
        :type value: Any
        """
        self.acquire_edit_permissions()

        self.__array.append(value)

        self.release_edit_permissions()

    def remove(self, value):
        """
        removes the value from the array
        :param value: the value to remove
        :type value: Any
        """
        self.semaphore_lock.acquire()
        if value not in self.__array:
            self.semaphore_lock.release()
            raise ValueError("SyncedArray.remove(value): value not in list")

        self.acquire_edit_permissions(1)

        self.__array.remove(value)

        self.release_edit_permissions()

    def __len__(self):
        """
        returns the length of the array
        :return: length of the array
        :rtype: int
        """
        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        length = self.__array.__len__()

        self.semaphore_lock.release()
        logging.debug("Released reading lock for {}".format(self.name))

        return length

    def __str__(self):
        """
        returns the array represented as a string
        :return: array representation
        :rtype: str
        """
        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        array_string = self.__array.__str__()

        self.semaphore_lock.release()
        logging.debug("Released reading lock for {}".format(self.name))

        return array_string

    def __getitem__(self, index):
        """
        returns the item at the index(th) place in the array
        :param index: index of item to return
        :type index: int
        :return: item at index(th) place
        :rtype: Any
        :raises: IndexError if index is not within range 0 < index < len(array) - 1
        """
        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        if index < 0 or index > len(self.__array) - 1:
            self.semaphore_lock.release()
            raise IndexError("SyncedArray.__getitem__(index): list index out of range")

        item = self.__array[index]

        self.semaphore_lock.release()
        logging.debug("Released reading lock for{}".format(self.name))

        return item

    def __setitem__(self, index, value):
        """
        sets the value of the item at the index(th) place in the array to value
        :param index: index of item to set to value
        :type index: int
        :param value: value to set the index(th) item to
        :type value: Any
        :raises: IndexError if index is not within range 0 < index < len(array) - 1
        """
        self.semaphore_lock.acquire()
        if index < 0 or index > len(self.__array) - 1:
            self.semaphore_lock.release()
            raise IndexError("SyncedArray.__setitem__(index, value): list index out of range")

        self.acquire_edit_permissions(acquired=1)

        self.__array[index] = value

        self.release_edit_permissions()

    @property
    def array(self):
        """
        returns a copy of the array, as a python list
        :return: array
        :rtype: list
        """
        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        array = self.__array.copy()

        self.semaphore_lock.release()
        logging.debug("Released reading lock for {}".format(self.name))

        return array


def main():
    pass


if __name__ == '__main__':
    main()
