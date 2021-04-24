"""
Author: Oren Sitton
File: SyncedArray.py
Python Version: 3.8
"""
import threading
import logging


class SyncedArray:
    """
    SyncedArray class, implements an array that can be used across multiple threads simultaneously

    Attributes
    ----------
    __array : list
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
    __init__(name="list", max_readers=2)
        initializes the list and locks
    __add__(other)
        adds together self and another SyncedArray or standard list
    __bool__()
        determines whether the array is empty or not
    __contains__(item)
        checks if the array contains an item
    __getitem__(index)
        returns the item at the index(th) place in the array
    __len__()
        returns the length of the array
    __radd__(other)
        adds together self and another SyncedArray or standard list (opposite of __add__(other))
    __setitem__(index, value)
        sets the value of the item at the index(th) place in the array to value
    __str__()
        returns the array as a string
    acquire_edit_permissions(acquired=0)
        acquires the write lock and read locks
    append(value)
        appends the value to the end of the array
    release_edit_permissions(released=0)
        releases the write and read locks
    remove(value)
        removes the value from the array
    array
        returns a copy of the array, as a python list
    """

    def __init__(self, name="list", max_readers=2):
        """
        initializes the array and the locks
        :param name: name of the array (to be shown in logging messages)
        :type name: str
        :param max_readers: maximum amount of simultaneous readers
        :type max_readers: int
        """
        self.__array = []
        self.name = name
        self.max_readers = max_readers
        self.semaphore_lock = threading.Semaphore(value=self.max_readers)
        self.write_lock = threading.Lock()

    def __add__(self, other):
        """
        adds together self and another SyncedArray or standard list
        :param other: SyncedArray/lst to add
        :type other: SyncedArray/list
        :return: combined lists
        :rtype: list
        :raises: NotImplementedError: addition of SyncedArray and received type not implemented
        """
        if isinstance(other, list):
            self.semaphore_lock.acquire()
            logging.debug("Acquired reading lock for {}".format(self.name))

            combined_lists = self.__array + other

            self.semaphore_lock.release()
            logging.debug("Released reading lock for {}".format(self.name))

            return combined_lists

        elif isinstance(other, SyncedArray):
            self.semaphore_lock.acquire()
            logging.debug("Acquired reading lock for {}".format(self.name))

            combined_lists = self.__array + other.array

            self.semaphore_lock.release()
            logging.debug("Released reading lock for {}".format(self.name))

            return combined_lists

        else:
            raise NotImplementedError("SyncedArray.__add__: addition of SyncedArray and received type not implemented")

    def __bool__(self):
        """
        determines whether array is empty
        :return: True if array is not empty, False if it is
        :rtype: bool
        """
        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        bool_value = self.__len__() != 0

        self.semaphore_lock.release()
        logging.debug("Released reading lock for {}".format(self.name))

        return bool_value

    def __contains__(self, item):
        """
        checks if the array contains an item
        :param item: item to check for
        :type item: Any
        :return: True if item is in the array, False if else
        :rtype: bool
        """

        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        contains = item in self.__array

        self.semaphore_lock.release()
        logging.debug("Released reading lock for {}".format(self.name))

        return contains

    def __getitem__(self, index):
        """
        returns the item at the index(th) place in the array
        :param index: index of item to return
        :type index: int
        :return: item at index(th) place
        :rtype: Any
        :raises: IndexError: index is not within range 0 < index < len(array) - 1
        """
        self.semaphore_lock.acquire()
        logging.debug("Acquired reading lock for {}".format(self.name))

        if index < 0 or index > len(self.__array) - 1:
            self.semaphore_lock.release()
            logging.debug("Released reading lock for {}".format(self.name))
            raise IndexError("SyncedArray.__getitem__: index is not within range")

        item = self.__array[index]

        self.semaphore_lock.release()
        logging.debug("Released reading lock for{}".format(self.name))

        return item

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

    def __radd__(self, other):
        """
        adds together self and another SyncedArray or standard list
        :param other: SyncedArray/lst to add
        :type other: SyncedArray/list
        :return: combined lists
        :rtype: list
        :raises: NotImplementedError: addition of SyncedArray and received type not implemented
        """
        if isinstance(other, list):
            self.semaphore_lock.acquire()
            logging.debug("Acquired reading lock for {}".format(self.name))

            combined_lists = other + self.__array

            self.semaphore_lock.release()
            logging.debug("Released reading lock for {}".format(self.name))

            return combined_lists

        elif isinstance(other, SyncedArray):
            self.semaphore_lock.acquire()
            logging.debug("Acquired reading lock for {}".format(self.name))

            combined_lists = other.array + self.__array

            self.semaphore_lock.release()
            logging.debug("Released reading lock for {}".format(self.name))

            return combined_lists

        else:
            raise NotImplementedError("SyncedArray.__radd__: addition of SyncedArray and received type not implemented")

    def __setitem__(self, index, value):
        """
        sets the value of the item at the index(th) place in the array to the value
        :param index: index of the item to set to the value
        :type index: int
        :param value: value to set the index(th) item to
        :type value: Any
        :raises: IndexError: index is not within range 0 < index < len(array) - 1
        """
        self.semaphore_lock.acquire()
        if index < 0 or index > len(self.__array) - 1:
            self.semaphore_lock.release()
            logging.debug("Released reading lock for {}".format(self.name))
            raise IndexError("SyncedArray.__setitem__: index is not within range")

        self.acquire_edit_permissions(acquired=1)

        self.__array[index] = value

        self.release_edit_permissions()

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

    def acquire_edit_permissions(self, acquired=0):
        """
        acquires the write lock and read locks
        :param acquired: amount of semaphore locks already acquired by caller (default 0)
        :type acquired: int
        """
        self.write_lock.acquire()
        logging.debug("Acquired write lock for {}".format(self.name))

        for x in range(self.max_readers - acquired):
            self.semaphore_lock.acquire()

        logging.debug("Acquired all reading locks for {}".format(self.name))

    def append(self, value):
        """
        appends the value to the end of the array
        :param value: value to append
        :type value: Any
        """
        self.acquire_edit_permissions()

        self.__array.append(value)

        self.release_edit_permissions()

    def release_edit_permissions(self, released=0):
        """
        releases the write and read locks
        :param released: amount of semaphore locks already released by caller (default 0)
        :type released: int
        """
        self.write_lock.release()
        logging.debug("Released write lock for {}".format(self.name))

        for x in range(self.max_readers - released):
            self.semaphore_lock.release()
        logging.debug("Released all reading locks for {}".format(self.name))

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
