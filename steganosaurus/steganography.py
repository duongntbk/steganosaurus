# -*- coding: utf-8 -*-

"""
This module provide steganography functionality, using picture file as medium
Steganography format:
+ Bcrypt hash of password: bytes, 60 bytes.
+ Salt for encryption key: 16 bytes (AES case).
+ Data size: integer, 64 bytes (zero-padded as needed).
+ Data: bytes, as much as needed.
"""

import argparse

import steganosaurus.constants as constants
import steganosaurus.hash_utils as hash_utils
from cryptography.fernet import InvalidToken
from steganosaurus.fernet_cryptor import FernetCryptor
from steganosaurus.otp_cryptor import OTPCryptor
from steganosaurus.picture_modifier import PictureModifier


class Steganography:
    '''
    Using steganography to hide secret data into picture.
    Data can be encrypted using Fernet encryption or OTP encryption.

    This package can be included into other project or called straight from command line.

    Supported encryption: 
    + Fernet encryption (AES-128) 
    + OTP encryption.

    Supported output format:
    + BMP and PNG image.

    Different between ste_password and password:
    + ste_password is used to check if medium contains hidden data.
    + password is encryption password.
    + For Fernet encryption, ste_password == password.
    + For OTP encryption, ste_password is SHA1 hash of pad, password is path to pad.
    '''

    def __init__(self, medium_modifer, encryptor):
        '''
        Initialization method,
        set medium_modifer object and encryptor here.
        '''

        self.medium_modifer = medium_modifer
        self.encryptor = encryptor

    def hide_file(self, password, medium, secret, format):
        '''
        Hide secret file into medium.
        Return binary value of medium file after adding secret file.
        '''

        self.medium_modifer.load_medium(medium)
        ste_password = self.encryptor.get_steganography_password(password)
        ste_password_hash = hash_utils.calculate_hash(ste_password, constants.HASH_FACTOR)
        self.medium_modifer.hide_data(ste_password_hash)

        # Only Fernet encryption needs salt for pbkdf, OTP does not need salt.
        if self.encryptor.need_pbkdf_salt:
            pbkdf_salt = self.encryptor.set_pbkdf_salt()
            self.medium_modifer.hide_data(pbkdf_salt)

        encrypted = self.encryptor.encrypt(password, secret)
        encrypted_size = len(encrypted).to_bytes(constants.DATA_LENGTH_SIZE, byteorder='big')
        self.medium_modifer.hide_data(encrypted_size)
        self.medium_modifer.hide_data(encrypted)
        
        return self.medium_modifer.export_medium(format)

    def get_file(self, password, medium):
        '''
        Retrieve secret file from medium.
        Return binary value of secret file retrieve from medium.
        '''

        self.medium_modifer.load_medium(medium)
        ste_password_hash = self.medium_modifer.get_data(constants.BCRYPT_HASH_SIZE)
        ste_password = self.encryptor.get_steganography_password(password)

        if not hash_utils.verify_hash(ste_password, ste_password_hash):
            raise PermissionError(constants.STEGANOGRAPHY_NOT_FOUND_ERROR)

        if self.encryptor.need_pbkdf_salt:
            pbkdf_salt = self.medium_modifer.get_data(constants.FERNET_SALT_SIZE)
            self.encryptor.pbkdf_salt = pbkdf_salt

        # Read 8 bytes and conver to int, this is the size of encrypted data.
        encrypted_file_size = self.medium_modifer.get_data(constants.DATA_LENGTH_SIZE)
        encrypted_file_size = int.from_bytes(encrypted_file_size, byteorder='big')
        encrypted = self.medium_modifer.get_data(encrypted_file_size)

        return self.encryptor.decrypt(password, encrypted)


def main():
    '''
    Entry point of script when run from command line.
    '''

    parser=argparse.ArgumentParser()
    parser.add_argument('--mode', help='Encryption/Decryption flag. Allowed value: encrypt/decrypt')
    parser.add_argument('--encryption', help='Encryption method. Use \'aes\' for Fernet encryption or use \'otp\' for OTP encryption')
    parser.add_argument('--key_stretch', help='Number of iteration use when deriving Fernet key from password. Must be a number. Required if encryption mode is aes')
    parser.add_argument('--level', help='Number of low-bit in each pixel uses to store secret data. Must be between 1~8')
    parser.add_argument('--medium', help='Path to medium file')
    parser.add_argument('--password', help='Password for Fernet encryption or path to OTP pad')
    parser.add_argument('--secret', help='Path to secret file. Required in encryption mode')
    parser.add_argument('--result', help='Path to result file')
    parser.add_argument('--format', help='Format of picture with steganography. Allowed value: BMP/PNG (case insensitive). Required in encryption mode')
    args=parser.parse_args()

    # Input check.
    if not verify_argument(args):
        print(constants.HELP_MSG)
        return

    try:
        # Fernet encryption use args.password to derive encryption key.
        if args.encryption == constants.MODE_FERNET:
            encryptor = FernetCryptor(int(args.key_stretch))
            password = args.password
        
        # OTP encryption read binary file at args.password and use it as encryption pad.
        else:
            encryptor = OTPCryptor()
            with open(args.password, 'rb') as f:
                password = f.read()

        modifier = PictureModifier(int(args.level))
        steganography = Steganography(modifier, encryptor)
        with open(args.medium, 'rb') as f:
            medium_data = f.read()

        if args.mode == constants.MODE_ENCRYPT:
            with open(args.secret, 'rb') as f:
                secret_data = f.read()
            file_with_secret = steganography.hide_file(password, medium_data, secret_data, args.format)
            with open(args.result, 'wb') as f:
                f.write(file_with_secret) 

        else:
            secret_data = steganography.get_file(password, medium_data)
            with open(args.result, 'wb') as f:
                f.write(secret_data)

    except FileNotFoundError as fe:
        print('Cannot open file, please check if file path is correct')
        print(str(fe))

    except InvalidToken as it:
        print('Decryption password is incorrect.')
        print(str(it))

    except ValueError as ve:
        print('An ValueError occurred. Please check value of all parameters')
        print(str(ve))

    except TypeError as te:
        print('An TypeError occurred. Please check type of all parameters')
        print(str(te))

    except Exception as e:
        print('An unknown error occurred.')
        print(str(e))


def verify_argument(args):
    '''
    Verify that the list of arguments passing to steganography.py is valid.
    '''

    # Verify all required arguments existed.
    if not (args.mode and args.encryption and args.level \
                and args.medium and args.password and args.result):
        return False

    if args.mode not in [constants.MODE_ENCRYPT, constants.MODE_DECRYPT]:
        return False

    if args.encryption not in [constants.MODE_FERNET, constants.MODE_OTP]:
        return False

    # In encryption mode, secret file path and result format is required.
    if args.mode == constants.MODE_ENCRYPT:
        if not (args.secret and args.format) or \
            args.format.lower() not in [constants.FORMAT_BMP, constants.FORMAT_PNG]:
            return False

    # When encryption mode is Fernet (AES-128), key-stretch iteration is required.
    if args.encryption == constants.MODE_FERNET and \
        not is_positive_number(args.key_stretch):
        return False

    if not is_positive_number(args.level):
        return False
    elif int(args.level) < 1 or int(args.level) > 8:
        return False
    
    return True


def is_positive_number(input):
    '''
    Check if an object can be converted into a positive number.
    Better to ask for forgiveness than for permission. 
    '''

    try:
        int_val = int(input)

    except:
        return False

    return int_val > 0


if __name__ == '__main__':
    main()
