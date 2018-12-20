# -*- coding: utf-8 -*-

"""
This module provides encryption/decryption for steganosaurus using Fernet encryption.
"""

import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import steganosaurus.constants as constants


class FernetCryptor:
    '''
    Encrypt/Decrypt data using Fernet (symmetric encryption).
    Fernet is basically AES128 in CBC mode with a SHA256 HMAC message authentication code.
    Spec: https://github.com/fernet/spec/blob/master/Spec.md
    '''

    def __init__(self, iteration):
        '''
        Initialization method,
        set number of hash iteration for key-stretching function here.
        '''

        self.iteration = iteration
        self.need_pbkdf_salt = True
        self.pbkdf_salt = None

    def generate_salt(self, length):
        '''
        Generate a random bytearray with given length to use as salt.
        '''

        if not isinstance(length, int):
            raise TypeError(constants.SALT_LENGTH_ERROR_MSG)

        if length < 0:
            raise ValueError(constants.SALT_LENGTH_ERROR_MSG)

        return os.urandom(length)

    def generate_key(self, salt, password):
        '''
        Stretch a password in an encryption key using PBKDF2HMAC.
        The number of hash iteration can be set at initialization.
        '''

        if not isinstance(salt, bytes):
            raise TypeError(constants.SALT_ERROR_MESSAGE)

        if len(salt) != constants.FERNET_SALT_SIZE:
            raise ValueError(constants.SALT_ERROR_MESSAGE)

        if not isinstance(password, str):
            raise TypeError(constants.PASSWORD_ERROR_MESSAGE)

        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=constants.FERNET_KEY_SIZE,
            salt=salt,
            iterations=self.iteration,
            backend=backend
        )

        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    def encrypt(self, password, data):
        '''
        Encrypt data using Fernet encryption with given key.
        '''

        key = self.generate_key(self.pbkdf_salt, password)
        f = Fernet(key)
        return f.encrypt(data)

    def decrypt(self, password, blob):
        '''
        Decrypt data using Fernet encryption with given key.
        '''

        key = self.generate_key(self.pbkdf_salt, password)
        f = Fernet(key)
        return f.decrypt(blob)

    def get_steganography_password(self, password):
        '''
        Create a password to verify if medium contains steganography or not.
        Because Fernet encryption is key-based, just return the encryption key.
        '''

        return password

    def set_pbkdf_salt(self):
        '''
        Create 16 bytes of random data and set it as salt for key-derived function.
        Return the salt to caller.
        '''

        salt = os.urandom(constants.FERNET_SALT_SIZE)
        self.pbkdf_salt = salt
        return salt