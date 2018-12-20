# -*- coding: utf-8 -*-

"""
This module provides encryption/decryption for steganosaurus using One-Time-Pad.
"""

import hashlib

import steganosaurus.constants as constants


class OTPCryptor:
    '''
    Encrypt/Decrypt data using One-Time-Pad.
    The pad MUST be true random or we won't get the full benefit of OTP.
    '''

    def __init__(self):
        '''
        Initialize function.
        Set has_pbkdf_salt flag to False because OTP does not need PBDKF.
        '''

        self.need_pbkdf_salt = False


    def encrypt(self, key, data):
        '''
        Encrypt data using OTP by xor-ing it with given key (pad).
        Pad and data must be of the same length for OTP to be fully secured.
        '''

        return self.xor_data(key, data)

    def decrypt(self, key, blob):
        '''
        Decrypt data using OTP by xor-ing it with given key (pad).
        Pad and data must be of the same length for OTP to be fully secured.
        '''

        return self.xor_data(key, blob)

    def xor_data(self, key, data):
        '''
        Xor data with given key (pad).
        Pad and data must be of the same length for OTP to be fully secured.
        '''

        if len(key) != len(data):
            raise ValueError(constants.PAD_LENGTH_ERROR)

        return bytes(a ^ b for (a, b) in zip(key, data))

    def get_steganography_password(self, pad):
        '''
        Create a password to verify if medium contains steganography or not.
        Return hex value of SHA-1 hash of pad.
        Because pad is true random, SHA-1 is secure enough.
        '''

        return hashlib.sha1(pad).hexdigest()