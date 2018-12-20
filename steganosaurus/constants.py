# -*- coding: utf-8 -*-

"""
Constants for steganosaurus.
"""

# Steganography format
BCRYPT_HASH_SIZE = 60
PBKDF_SALT_SIZE = 16
DATA_LENGTH_SIZE = 8

# Constants
KEY_STRETCH_ITERATION = 100000
FERNET_KEY_SIZE = 32
FERNET_SALT_SIZE = 16
DEFAULT_STEGANOGRAPHY_LEVEL = 2
MIN_STEGANOGRAPHY_LEVEL = 1
MAX_STEGANOGRAPHY_LEVEL = 8
HASH_FACTOR = 8

# Error messages
SALT_LENGTH_ERROR_MSG = 'Cannot generate salt because length is invalid'
SALT_ERROR_MESSAGE = 'Cannot generate encryption key because salt is invalid'
PASSWORD_ERROR_MESSAGE = 'Cannot generate encryption key because password is invalid'
PAD_LENGTH_ERROR = 'When using OTP, pad and data must be of the same length'
WRONG_KEY_MSG = 'Cannot decrypt data because the key is incorrect'
STEGANOGRAPHY_LEVEL_VALUE_ERROR_MSG = 'Steganography level must be between 1 ~ 8'
STEGANOGRAPHY_LEVEL_TYPE_ERROR_MSG = 'Steganography level must be a number'
PICTURE_NOT_LOADED_ERROR_MSG = 'Please load original picture first'
MAX_COLOR_INDEX = 3
INPUT_DATA_ERROR_MSG = 'Cannot hide data into image, data must be in bytes format'
DATA_SIZE_ERROR_MSG = 'Data is too big, please choose a bigger medium'
GET_DATA_PARA_TYPE_ERROR_MSG = 'Size parameter of get_data must be integer'
GET_DATA_PARA_VALUE_ERROR_MSG = 'Size parameter of get_data is too big'
GET_DATA_PARA_VALUE_NEGATIVE_MSG = 'Size parameter of get_data must be bigger than 0'
STEGANOGRAPHY_NOT_FOUND_ERROR = 'Medium does not contains steganography or password is incorrect'


# Commandline option
MODE_ENCRYPT = 'encrypt'
MODE_DECRYPT = 'decrypt'
MODE_FERNET = 'aes'
MODE_OTP = 'otp'
FORMAT_BMP = 'bmp'
FORMAT_PNG = 'png'

# Help message for steganosaurus.
HELP_MSG = '\n' + \
            'Input parameter was incorrect\n' + \
            'Try \'python steganography.py -h\' for more information'
