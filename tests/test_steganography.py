# -*- coding: utf-8 -*-

"""
Test for steganography.
"""

import argparse
import os
from collections import namedtuple

import pytest
import steganosaurus.constants as constants
import steganosaurus.hash_utils as hash_utils
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import mocker
from steganosaurus.fernet_cryptor import FernetCryptor
from steganosaurus.otp_cryptor import OTPCryptor
from steganosaurus.picture_modifier import PictureModifier
from steganosaurus.steganography import Steganography
from steganosaurus.steganography import \
    is_positive_number as is_positive_number
from steganosaurus.steganography import main as steganography_main
from steganosaurus.steganography import verify_argument as steganography_verify


monkeypatch = MonkeyPatch()
fernet_cryptor = FernetCryptor(constants.KEY_STRETCH_ITERATION)
otp_cryptor = OTPCryptor()
picture_modifier = PictureModifier(2)
secret_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'secret.txt')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'medium.bmp')
with open(secret_path, mode='rb') as file:
    secret_data = file.read()
with open(test_data_path, mode='rb') as file:
    medium_data = file.read()
    


def test_hide_file_fernet(mocker):
    '''
    Can hide hidden data into medium.
    Hidden data is encrypted using Fernet encrpytion (AES-128).
    '''

    steganography = Steganography(picture_modifier, fernet_cryptor)

    password = 'dummy_password'
    format = 'BMP'
    password_hash = os.urandom(constants.BCRYPT_HASH_SIZE)
    pbkdf_salt = os.urandom(constants.FERNET_SALT_SIZE)
    encrypted = os.urandom(128)
    medium_with_secret = os.urandom(1024)

    mocker.patch.object(PictureModifier, 'load_medium')
    mocker.patch.object(FernetCryptor, 'get_steganography_password')
    FernetCryptor.get_steganography_password.return_value = password
    mocker.patch.object(hash_utils, 'calculate_hash')
    hash_utils.calculate_hash.return_value = password_hash
    mocker.patch.object(PictureModifier, 'hide_data')
    mocker.patch.object(FernetCryptor, 'set_pbkdf_salt')
    FernetCryptor.set_pbkdf_salt.return_value = pbkdf_salt
    fernet_cryptor.pbkdf_salt = pbkdf_salt
    mocker.patch.object(FernetCryptor, 'encrypt')
    FernetCryptor.encrypt.return_value = encrypted
    mocker.patch.object(PictureModifier, 'export_medium')
    PictureModifier.export_medium.return_value = medium_with_secret

    assert steganography.hide_file(password, medium_data, secret_data, format) == medium_with_secret

    assert fernet_cryptor.need_pbkdf_salt
    PictureModifier.load_medium.assert_called_once_with(medium_data)
    FernetCryptor.get_steganography_password.assert_called_once_with(password)
    hash_utils.calculate_hash.assert_called_once_with(password, constants.HASH_FACTOR)
    PictureModifier.hide_data.assert_any_call(password_hash)
    FernetCryptor.set_pbkdf_salt.assert_called_once_with()
    assert fernet_cryptor.pbkdf_salt == pbkdf_salt
    PictureModifier.hide_data.assert_any_call(pbkdf_salt)
    FernetCryptor.encrypt.assert_any_call(password, secret_data)
    PictureModifier.hide_data.assert_any_call(len(encrypted).to_bytes(constants.DATA_LENGTH_SIZE, byteorder='big'))
    PictureModifier.hide_data.assert_any_call(encrypted)
    PictureModifier.export_medium.assert_any_call(format)


def test_hide_file_otp(mocker):
    '''
    Can hide hidden data into medium.
    Hidden data is encrypted using OTP encryption.
    '''

    steganography = Steganography(picture_modifier, otp_cryptor)

    password = 'pad.bin'
    steganography_password = '8a062762b30368402c04958a419eb1f857c5d5a1'
    medium_path = 'dummy_medium'
    format = 'BMP'
    password_hash = os.urandom(constants.BCRYPT_HASH_SIZE)
    encrypted = os.urandom(128)
    medium_with_secret = os.urandom(1024)

    mocker.patch.object(PictureModifier, 'load_medium')
    mocker.patch.object(OTPCryptor, 'get_steganography_password')
    OTPCryptor.get_steganography_password.return_value = steganography_password
    mocker.patch.object(hash_utils, 'calculate_hash')
    hash_utils.calculate_hash.return_value = password_hash
    mocker.patch.object(PictureModifier, 'hide_data')
    mocker.patch.object(OTPCryptor, 'encrypt')
    OTPCryptor.encrypt.return_value = encrypted
    mocker.patch.object(PictureModifier, 'export_medium')
    PictureModifier.export_medium.return_value = medium_with_secret

    assert steganography.hide_file(password, medium_path, secret_data, format) == medium_with_secret

    assert not otp_cryptor.need_pbkdf_salt
    PictureModifier.load_medium.assert_called_once_with(medium_path)
    OTPCryptor.get_steganography_password.assert_called_once_with(password)
    hash_utils.calculate_hash.assert_called_once_with(steganography_password, constants.HASH_FACTOR)
    PictureModifier.hide_data.assert_any_call(password_hash)
    OTPCryptor.encrypt.assert_any_call(password, secret_data)
    PictureModifier.hide_data.assert_any_call(len(encrypted).to_bytes(constants.DATA_LENGTH_SIZE, byteorder='big'))
    PictureModifier.hide_data.assert_any_call(encrypted)
    PictureModifier.export_medium.assert_any_call(format)


def test_get_file_fernet(mocker):
    '''
    Can retrieve secret file from medium.
    Secret file is encrypted using Fernet encrpytion (AES-128).
    '''

    steganography = Steganography(picture_modifier, fernet_cryptor)
    password = 'dummy_password'
    medium_path = 'dummy_medium'
    password_hash = os.urandom(constants.BCRYPT_HASH_SIZE)
    pbkdf_salt = os.urandom(constants.FERNET_SALT_SIZE)
    encrypted = os.urandom(2048)
    encrypted_file_size = len(encrypted).to_bytes(constants.DATA_LENGTH_SIZE, byteorder='big')
    hidden_data_list = [
        password_hash,
        pbkdf_salt,
        encrypted_file_size,
        encrypted
    ]
    secret_data = os.urandom(1024)

    mocker.patch.object(PictureModifier, 'load_medium')
    mocker.patch.object(PictureModifier, 'get_data', side_effect=hidden_data_list)
    mocker.patch.object(hash_utils, 'verify_hash')
    hash_utils.verify_hash.return_value = True
    mocker.patch.object(FernetCryptor, 'get_steganography_password')
    FernetCryptor.get_steganography_password.return_value = password
    mocker.patch.object(FernetCryptor, 'decrypt')
    FernetCryptor.decrypt.return_value = secret_data

    assert steganography.get_file(password, medium_path) == secret_data

    assert fernet_cryptor.need_pbkdf_salt
    PictureModifier.load_medium.assert_called_once_with(medium_path)
    PictureModifier.get_data.assert_any_call(constants.BCRYPT_HASH_SIZE)
    FernetCryptor.get_steganography_password.assert_called_once_with(password)
    PictureModifier.get_data.assert_any_call(constants.FERNET_SALT_SIZE)
    assert fernet_cryptor.pbkdf_salt == pbkdf_salt
    PictureModifier.get_data.assert_any_call(len(encrypted))
    FernetCryptor.decrypt.assert_called_once_with(password, encrypted)


def test_get_file_otp(mocker):
    '''
    Can retrieve secret file from medium.
    Secret file is encrypted using OTP encrpytion.
    '''

    steganography = Steganography(picture_modifier, otp_cryptor)
    password = 'pad.bin'
    steganography_password = '8a062762b30368402c04958a419eb1f857c5d5a1'
    medium_path = 'dummy_medium'
    password_hash = os.urandom(constants.BCRYPT_HASH_SIZE)
    encrypted = os.urandom(2048)
    encrypted_file_size = len(encrypted).to_bytes(constants.DATA_LENGTH_SIZE, byteorder='big')
    hidden_data_list = [
        password_hash,
        encrypted_file_size,
        encrypted
    ]
    secret_data = os.urandom(1024)

    mocker.patch.object(PictureModifier, 'load_medium')
    mocker.patch.object(PictureModifier, 'get_data', side_effect=hidden_data_list)
    mocker.patch.object(hash_utils, 'verify_hash')
    hash_utils.verify_hash.return_value = True
    mocker.patch.object(OTPCryptor, 'get_steganography_password')
    OTPCryptor.get_steganography_password.return_value = steganography_password
    mocker.patch.object(OTPCryptor, 'decrypt')
    OTPCryptor.decrypt.return_value = secret_data

    assert steganography.get_file(password, medium_path) == secret_data

    assert not otp_cryptor.need_pbkdf_salt
    PictureModifier.load_medium.assert_called_once_with(medium_path)
    PictureModifier.get_data.assert_any_call(constants.BCRYPT_HASH_SIZE)
    OTPCryptor.get_steganography_password.assert_called_once_with(password)
    PictureModifier.get_data.assert_any_call(len(encrypted))
    OTPCryptor.decrypt.assert_called_once_with(password, encrypted)


def test_get_file_wrong_password(mocker):
    '''
    If steganography password is incorrect, raise PermissionError.
    '''

    encryptors = [
        fernet_cryptor, 
        otp_cryptor
    ]

    for encryptor in encryptors:
        steganography = Steganography(picture_modifier, encryptor)
        password = 'dummy_password'
        otp_pad = os.urandom(20)
        medium_path = 'dummy_medium'
        password_hash = os.urandom(constants.BCRYPT_HASH_SIZE)

        mocker.patch.object(PictureModifier, 'load_medium')
        mocker.patch.object(PictureModifier, 'get_data')
        PictureModifier.get_data.return_value = password_hash
        mocker.patch.object(hash_utils, 'verify_hash')
        hash_utils.verify_hash.return_value = False
        mocker.patch.object(FernetCryptor, 'get_steganography_password')
        FernetCryptor.get_steganography_password.return_value = password

        with pytest.raises(PermissionError) as pe:
            if isinstance(encryptor, FernetCryptor):
                steganography.get_file(password, medium_path)
            else:
                steganography.get_file(otp_pad, medium_path)
        assert str(pe.value) == constants.STEGANOGRAPHY_NOT_FOUND_ERROR


def test_main_encryption_fernet(mocker):
    '''
    This package can be called straight from command line.
    Can encrypt data using Fernet encryption (AES-128).
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args = my_namespace(mode='encrypt', encryption='aes', key_stretch='100000', \
                level='2', medium='medium.bmp', password='password', \
                secret='secret.txt', result='hidden.bmp', format='BMP')

    dummyEncryptor = FernetCryptor(int(args.key_stretch))
    dummyModifier = PictureModifier(int(args.level))

    with mocker.patch('builtins.open', new_callable=mocker.mock_open()) as mo:
        with monkeypatch.context() as m:
            m.setattr(argparse.ArgumentParser, 'parse_args', lambda self: args)
            mocker.patch.object(FernetCryptor, '__init__')
            FernetCryptor.__init__.return_value = None
            mocker.patch.object(PictureModifier, '__init__')
            PictureModifier.__init__.return_value = None
            mocker.patch.object(Steganography, 'hide_file')

            steganography_main()
            mo.assert_any_call(args.medium, 'rb')
            mo.assert_any_call(args.secret, 'rb')
            mo.assert_any_call(args.result, 'wb')
            FernetCryptor.__init__.assert_called_once_with(int(args.key_stretch))
            PictureModifier.__init__.assert_called_once_with(int(args.level))
            assert Steganography.hide_file.call_count == 1


def test_main_decryption_fernet(mocker):
    '''
    This package can be called straight from command line.
    Can decrypt data using Fernet encryption (AES-128).
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args = my_namespace(mode='decrypt', encryption='aes', key_stretch='100000', \
                level='2', medium='medium.bmp', password='password', \
                secret='secret.txt', result='hidden.bmp', format='BMP')

    dummyEncryptor = FernetCryptor(int(args.key_stretch))
    dummyModifier = PictureModifier(int(args.level))

    with mocker.patch('builtins.open', new_callable=mocker.mock_open()) as mo:
        with monkeypatch.context() as m:
            m.setattr(argparse.ArgumentParser, 'parse_args', lambda self: args)
            mocker.patch.object(FernetCryptor, '__init__')
            FernetCryptor.__init__.return_value = None
            mocker.patch.object(PictureModifier, '__init__')
            PictureModifier.__init__.return_value = None
            mocker.patch.object(Steganography, 'get_file')

            steganography_main()
            mo.assert_any_call(args.medium, 'rb')
            mo.assert_any_call(args.result, 'wb')
            FernetCryptor.__init__.assert_called_once_with(int(args.key_stretch))
            PictureModifier.__init__.assert_called_once_with(int(args.level))
            assert Steganography.get_file.call_count == 1


def test_main_encryption_otp(mocker):
    '''
    This package can be called straight from command line.
    Can encrypt data using OTP encryption.
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args = my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                level='2', medium='medium.bmp', password='key.bin', \
                secret='secret.txt', result='hidden.bmp', format='BMP')

    dummyEncryptor = OTPCryptor()
    dummyModifier = PictureModifier(int(args.level))

    with mocker.patch('builtins.open', new_callable=mocker.mock_open()) as mo:
        with monkeypatch.context() as m:
            m.setattr(argparse.ArgumentParser, 'parse_args', lambda self: args)
            mocker.patch.object(OTPCryptor, '__init__')
            OTPCryptor.__init__.return_value = None
            mocker.patch.object(PictureModifier, '__init__')
            PictureModifier.__init__.return_value = None
            mocker.patch.object(Steganography, 'hide_file')

            steganography_main()
            mo.assert_any_call(args.password, 'rb')
            mo.assert_any_call(args.secret, 'rb')
            mo.assert_any_call(args.result, 'wb')
            OTPCryptor.__init__.assert_called_once_with()
            PictureModifier.__init__.assert_called_once_with(int(args.level))
            assert Steganography.hide_file.call_count == 1


def test_main_decryption_otp(mocker):
    '''
    This package can be called straight from command line.
    Can decrypt data using OTP encryption.
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args = my_namespace(mode='decrypt', encryption='otp', key_stretch=None, \
                level='2', medium='medium.bmp', password='key.bin', \
                secret='secret.txt', result='hidden.bmp', format='BMP')

    dummyEncryptor = OTPCryptor()
    dummyModifier = PictureModifier(int(args.level))

    with mocker.patch('builtins.open', new_callable=mocker.mock_open()) as mo:
        with monkeypatch.context() as m:
            m.setattr(argparse.ArgumentParser, 'parse_args', lambda self: args)
            mocker.patch.object(OTPCryptor, '__init__')
            OTPCryptor.__init__.return_value = None
            mocker.patch.object(PictureModifier, '__init__')
            PictureModifier.__init__.return_value = None
            mocker.patch.object(Steganography, 'get_file')

            steganography_main()
            mo.assert_any_call(args.password, 'rb')
            mo.assert_any_call(args.result, 'wb')
            OTPCryptor.__init__.assert_called_once_with()
            PictureModifier.__init__.assert_called_once_with(int(args.level))
            assert Steganography.get_file.call_count == 1


def test_main_invalid_argument(mocker):
    '''
    If any argument is invalid, stop executing.
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args_list = [
        my_namespace(mode=None, encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption=None, key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level=None, medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password=None, \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret=None, result='hidden.bmp', format='BMP'), \
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result=None, format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result='hidden.bmp', format=None),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP1'), \
        my_namespace(mode='decrypt', encryption='otp1', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='otp', key_stretch=None, \
                        level='a', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch=None, \
                        level='-2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch=None, \
                        level='9', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result=None, format='BMP')
    ]

    for args in args_list:
        with monkeypatch.context() as m:
            m.setattr(argparse.ArgumentParser, 'parse_args', lambda self: args)
            mocker.patch.object(Steganography, 'get_file')
            mocker.patch.object(Steganography, 'hide_file')
            mocker.patch.object(OTPCryptor, '__init__')
            OTPCryptor.__init__.return_value = None
            mocker.patch.object(FernetCryptor, '__init__')
            FernetCryptor.__init__.return_value = None
            mocker.patch.object(PictureModifier, '__init__')
            PictureModifier.__init__.return_value = None

            steganography_main()

            OTPCryptor.__init__.assert_not_called()
            FernetCryptor.__init__.assert_not_called()
            PictureModifier.__init__.assert_not_called()
            Steganography.get_file.assert_not_called()
            Steganography.hide_file.assert_not_called()


def test_verify_argument():
    '''
    Can verify arguments list.
    If all arguments are valid, return True.
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args_list = [
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='otp', key_stretch=None, \
                        level='1', medium='medium.bmp', password='password', \
                        secret=None, result='secret.txt', format=None), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch='100000', \
                        level='8', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='PNG'), \
    ]

    for args in args_list:
        assert steganography_verify(args) == True


def test_verify_argument_error():
    '''
    If any argument in arguments list is invalid, return False.
    '''

    my_namespace = namedtuple('Namespace', ['mode', 'encryption', 'key_stretch', 'level','medium','password','secret','result','format'])

    args_list = [
        my_namespace(mode=None, encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption=None, key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level=None, medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password=None, \
                        secret='secret.txt', result='hidden.bmp', format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret=None, result='hidden.bmp', format='BMP'), \
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result=None, format='BMP'),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result='hidden.bmp', format=None),
        my_namespace(mode='encrypt', encryption='otp', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='JPEG'), \
        my_namespace(mode='decrypt', encryption='otp1', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='otp', key_stretch=None, \
                        level='a', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch=None, \
                        level='2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch=None, \
                        level='-2', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='aes', key_stretch=None, \
                        level='9', medium='medium.bmp', password='password', \
                        secret='secret.txt', result='hidden.bmp', format='BMP'), \
        my_namespace(mode='decrypt', encryption='otp', key_stretch=None, \
                        level='2', medium=None, password='password', \
                        secret='secret.txt', result=None, format='BMP')
    ]

    for args in args_list:
        assert steganography_verify(args) == False


def test_is_positive_number():
    '''
    Can check if an object can be converted into a positive number.
    '''

    inputs = [
        '1',
        '10',
        '+10',
        '20 ',
        ' 15',
        None,
        [],
        object,
        '-1',
        '-20 ',
        ' -30',
    ]

    results = [
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
    ]

    for input, result in zip(inputs, results):
        assert is_positive_number(input) == result