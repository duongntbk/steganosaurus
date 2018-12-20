# -*- coding: utf-8 -*-

"""
Test for otp_cryptor.
"""

import builtins
import hashlib
import os
import unittest.mock as mock

import pytest
import steganosaurus.constants as constants
from pytest_mock import mocker
from steganosaurus.otp_cryptor import OTPCryptor

otp_cryptor = OTPCryptor()


# File content for test_load_pad.
file_content = os.urandom(100)


def test_xor_data():
    '''
    Can xor data with pad.
    '''

    data_list = [
        bytes(False),
        bytes.fromhex('ff'),
        bytes.fromhex('7c'),
        bytes.fromhex('0a0b0d5785ac753d42c66971526c96885797b721206682b2fb8de4b7631371d4'),
        bytes.fromhex('432ea4446c0879c965b4e67faaed3a96ffe55021727f1a3dcb61416b9bb23012'),
    ]

    pads = [
        bytes(False),
        bytes.fromhex('00'),
        bytes.fromhex('b8'),
        bytes.fromhex('8846d4812675ed2aefea1981687e667004364177b2c3e3f1c2809413f1371c80'),
        bytes.fromhex('c23d3141a5d7226fa3e4880ecd8182e8a047be400fe0afea1869c2db8e782c92'),
    ]

    results = [
        bytes(False),
        bytes.fromhex('ff'),
        bytes.fromhex('c4'),
        bytes.fromhex('824dd9d6a3d99817ad2c70f03a12f0f853a1f65692a56143390d70a492246d54'),
        bytes.fromhex('81139505c9df5ba6c6506e71676cb87e5fa2ee617d9fb5d7d30883b015ca1c80'),
    ]

    for data, pad, result in zip(data_list, pads, results):
        assert otp_cryptor.xor_data(pad, data) == result


def test_xor_data_length_error():
    '''
    When encrypting/decrypting, if pad length and data length is equals, raise ValueError.
    '''

    data_list = [
        os.urandom(0),
        os.urandom(100),
        os.urandom(1000),
        os.urandom(2**16)
    ]

    pads = [
        os.urandom(1),
        os.urandom(50),
        os.urandom(0),
        os.urandom(2**17)
    ]

    for data, pad in zip(data_list, pads):
        with pytest.raises(ValueError) as ve:
            otp_cryptor.xor_data(pad, data)
        assert str(ve.value) == constants.PAD_LENGTH_ERROR


def test_encrypt(mocker):
    '''
    Can encrypt data using OTP.
    '''

    data_list = [
        os.urandom(0),
        os.urandom(1),
        os.urandom(100),
        os.urandom(2048),
    ]

    pads = [
        os.urandom(0),
        os.urandom(1),
        os.urandom(100),
        os.urandom(2048),
    ]

    for pad, data in zip(pads, data_list):
        mocker.patch.object(OTPCryptor, 'xor_data')

        otp_cryptor.encrypt(pad, data)
        OTPCryptor.xor_data.assert_called_once_with(pad, data)


def test_decrypt(mocker):
    '''
    Can decrypt data using OTP.
    '''

    blobs = [
        os.urandom(0),
        os.urandom(1),
        os.urandom(100),
        os.urandom(2048),
    ]

    pads = [
        os.urandom(0),
        os.urandom(1),
        os.urandom(100),
        os.urandom(2048),
    ]

    for pad, blob in zip(pads, blobs):
        mocker.patch.object(OTPCryptor, 'xor_data')

        otp_cryptor.decrypt(pad, blob)
        OTPCryptor.xor_data.assert_called_once_with(pad, blob)


def test_get_steganography_password():
    '''
    Can create a password to verify if medium contains steganography or not.
    '''

    sha1hash = hashlib.sha1(file_content).hexdigest()
    assert otp_cryptor.get_steganography_password(file_content) == sha1hash