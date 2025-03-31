import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import hashlib
import random
from multiprocessing import Process, Queue, Value
import time
import os
from cryptography.fernet import Fernet  # Requires `pip install cryptography`

# Simulated Node Class
class Node:
    def __init__(self, node_id, active=True):
        self.node_id = node_id
        self.active = active
        self.storage = {}

    def store(self, filename_chunk, data, checksum):
        if self.active:
            self.storage[filename_chunk] = (data, checksum)
            print(f"Node {self.node_id}: Stored {filename_chunk}")
            return True
        return False

    def retrieve(self, filename_chunk):
        if self.active and filename_chunk in self.storage:
            data, checksum = self.storage[filename_chunk]
            if hashlib.sha256(data).hexdigest() == checksum:
                print(f"Node {self.node_id}: Retrieved {filename_chunk}")
                return data
            else:
                print(f"Node {self.node_id}: Checksum mismatch for {filename_chunk}")
        print(f"Node {self.node_id}: {filename_chunk} not found or inactive")
        return None

    def delete(self, filename_chunk):
        if self.active and filename_chunk in self.storage:
            del self.storage[filename_chunk]
            return True
        return False

    def fail(self):
        self.active = False

    def recover(self):
        self.active = True
