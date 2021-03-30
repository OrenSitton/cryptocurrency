"""
Author: Oren Sitton
File: synced_array.py
Python Version: 3.8
Description: 
"""
import threading
import logging


class SyncedArray:
    def __init__(self, name="list"):
        self.list = []
        self.name = name
        self.max_readers = 2
        self.semaphore_lock = threading.Semaphore(value=self.max_readers)
        self.write_lock = threading.Lock()

    def acquire_edit_permissions(self):
        self.write_lock.acquire()
        logging.info("Acquired write lock for {}".format(self.name))

        for x in range(self.max_readers):
            self.semaphore_lock.acquire()

        logging.info("Acquired all reading locks for {}".format(self.name))

    def release_edit_permissions(self):
        self.write_lock.release()
        logging.info("Released write lock for {}".format(self.name))

        for x in range(self.max_readers):
            self.semaphore_lock.release()
        logging.info("Released all reading locks for {}".format(self.name))

    def __len__(self):
        self.semaphore_lock.acquire()
        logging.info("Acquired reading lock for {}".format(self.name))

        length = self.list.__len__()

        self.semaphore_lock.release()
        logging.info("Released reading lock for {}".format(self.name))

        return length

    def __getitem__(self, index):
        self.semaphore_lock.acquire()
        logging.info("Acquired reading lock for {}".format(self.name))

        item = self.list[index]

        self.semaphore_lock.release()
        logging.info("Released reading lock for{}".format(self.name))

        return item

    def __setitem__(self, index, value):
        self.acquire_edit_permissions()

        self.list[index] = value

        self.release_edit_permissions()

    def append(self, value):
        self.acquire_edit_permissions()

        self.list.append(value)

        self.release_edit_permissions()

    def remove(self, value):
        self.acquire_edit_permissions()

        self.list.remove(value)

        self.release_edit_permissions()

    def __str__(self):
        self.semaphore_lock.acquire()
        logging.info("Acquired reading lock for {}".format(self.name))

        list_string = self.list.__str__()

        self.semaphore_lock.release()
        logging.info("Released reading lock for {}".format(self.name))

        return list_string


def main():
    pass


if __name__ == '__main__':
    main()
