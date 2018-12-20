# -*- coding: utf-8 -*-

"""
Test for fernet_cryptor.
"""

import os

import pytest
from _pytest.monkeypatch import MonkeyPatch
from cryptography.fernet import InvalidToken

import steganosaurus.constants as constants
from steganosaurus.fernet_cryptor import FernetCryptor

fernet_cryptor = FernetCryptor(constants.KEY_STRETCH_ITERATION)
monkeypatch = MonkeyPatch()


def test_generate_salt_length():
    '''
    Can generate salt with given length.
    '''

    lengths = [
        1,
        10,
        16
    ]

    for length in lengths:
        result = fernet_cryptor.generate_salt(length)
        assert len(result) == length
        assert isinstance(result, bytes)


def test_generate_salt_value():
    '''
    Can generate salt with given length.
    '''

    lengths = [
        1,
        10,
        16
    ]

    values = [
        bytes.fromhex('8d'),
        bytes.fromhex('da0ad970d5a16dbe5f04'),
        bytes.fromhex('c77e44fa1052a502ff38aa9546ec2dc9')
    ]

    for length, value in zip(lengths, values):
        with monkeypatch.context() as m:
            m.setattr(os, 'urandom', lambda length: value)

            result = fernet_cryptor.generate_salt(length)
            assert len(result) == length
            assert isinstance(result, bytes)
            assert result == value


def test_generate_salt_error():
    '''
    If salt type is invalid, raise TypeError.
    '''

    lengths = [
        'string',
        None,
        {}
    ]

    for length in lengths:
        with pytest.raises(TypeError) as te:
            fernet_cryptor.generate_salt(length)
        assert str(te.value) == constants.SALT_LENGTH_ERROR_MSG


def test_generate_salt_value_error():
    '''
    If salt length is invalid, raise ValueError.
    '''

    lengths = [
        -1,
        -100,
        -2048
    ]

    for length in lengths:
        with pytest.raises(ValueError) as ve:
            fernet_cryptor.generate_salt(length)
        assert str(ve.value) == constants.SALT_LENGTH_ERROR_MSG


def test_generate_key():
    '''
    Can strech a given password into an encryption key.
    '''

    salts = [
        bytes.fromhex('d921cf678bdd657efc57231ac55ff3dc'),
        bytes.fromhex('c77e44fa1052a502ff38aa9546ec2dc9'),
        bytes.fromhex('1766064d71f321bd43e5501d0adc5941')
    ]

    passwords = [
        'password',
        'letmein',
        '27101990'
    ]

    keys = [
        b'akC4B00sAaQCtG8XkLwh29LCG-0RL7hcnzuKRkUzrGk=',
        b'yQFziPHl27f8uiKbWHk2Avpfa16DXLd8IbBtw5YfGfA=',
        b'54xgfoc7MTGt6PjSiluxP7OSIl2OPJnsdh3MIhEmYx0='
    ]

    for salt, password, key in zip(salts, passwords, keys):
        assert key == fernet_cryptor.generate_key(salt, password)


def test_generate_key_salt_error():
    '''
    If salt type is invaid, raise TypeError.
    '''

    salts = [
        1,
        None,
        []
    ]

    dummy_password = 'dummy'

    for salt in salts:
        with pytest.raises(TypeError) as te:
            # Use dummy password because
            # we only care if an exception is raised or not.
            fernet_cryptor.generate_key(salt, dummy_password)
        assert str(te.value) == constants.SALT_ERROR_MESSAGE


def test_generate_key_salt_value_error():
    '''
    If salt length is invaid, raise ValueError.
    '''

    salts = [
        bytes.fromhex('da0ad970d5a16dbe5f04')
    ]

    dummy_password = 'dummy'

    for salt in salts:
        with pytest.raises(ValueError) as ve:
            # Use dummy password because
            # we only care if an exception is raised or not.
            fernet_cryptor.generate_key(salt, dummy_password)
        assert str(ve.value) == constants.SALT_ERROR_MESSAGE


def test_generate_key_password_error():
    '''
    If password type is invaid, raise TypeError.
    '''

    dummy_salt = bytes.fromhex('d921cf678bdd657efc57231ac55ff3dc')

    passwords = [
        1,
        None,
        []
    ]

    for password in passwords:
        with pytest.raises(TypeError) as te:
            # Use dummy salt because
            # we only care if an exception is raised or not.
            fernet_cryptor.generate_key(dummy_salt, password)
        assert str(te.value) == constants.PASSWORD_ERROR_MESSAGE


def test_encryption_decryption():
    '''
    Can encrypt and decrypt data with given key.
    '''

    keys = [
        b'akC4B00sAaQCtG8XkLwh29LCG-0RL7hcnzuKRkUzrGk=',
        b'yQFziPHl27f8uiKbWHk2Avpfa16DXLd8IbBtw5YfGfA=',
        b'54xgfoc7MTGt6PjSiluxP7OSIl2OPJnsdh3MIhEmYx0='
    ]

    data_list = [
        'This is the first data'.encode('utf-8'),
        b'',
        'これは日本語です'.encode('utf-8')
    ]

    password = 'dummy_password'
    salt = bytes(16)

    with monkeypatch.context() as m:
        for key, data in zip(keys, data_list):
            m.setattr(fernet_cryptor, 'pbkdf_salt', salt)
            m.setattr(fernet_cryptor, 'generate_key', lambda salt, password: key)
            blob = fernet_cryptor.encrypt(password, data)
            assert data == fernet_cryptor.decrypt(password, blob)


def test_encryption_descryption_wrong_key():
    '''
    Cannot decrypt data without the correct key.
    '''

    # Encryption passwords.
    e_passwords = [
        'secret',
        'admin',
        'letmeit'
    ]

    # Decryption passwords.
    d_passwords = [
        'secret1',
        'admin1',
        'letmeit1'
    ]

    salt = bytes(16)

    with monkeypatch.context() as m:
        m.setattr(fernet_cryptor, 'pbkdf_salt', salt)

        for e_password, d_password in zip(e_passwords, d_passwords):
            # We only care if an exception is raised.
            dummy_data = os.urandom(10)

            with pytest.raises(InvalidToken):
                blob = fernet_cryptor.encrypt(e_password, dummy_data)
                fernet_cryptor.decrypt(d_password, blob)


def test_get_steganography_password():
    '''
    Can create a password to verify if medium contains steganography or not.
    '''

    passwords = [
        'これは日本語'
        'password',
        '1234567890qwertyuiop!"#$%&\'()"',
        ''
    ]

    for password in passwords:
        assert fernet_cryptor.get_steganography_password(password) == password


def test_set_pbkdf_salt():
    '''
    Can generate and set a random salt for key-derived function.
    '''

    salts = [
        bytes.fromhex('c19d95f7a853795e992e14ead3418cfe'),
        bytes.fromhex('f3f81c1889efa7d9e0dc3e5d0aac11e5'),
        bytes.fromhex('da1059f7ac3633ee0fcfcbd52c5407a4')
    ]

    for salt in salts:
        with monkeypatch.context() as m:
            m.setattr(os, 'urandom', lambda size: salt)
            assert fernet_cryptor.set_pbkdf_salt() == salt
            assert fernet_cryptor.pbkdf_salt == salt