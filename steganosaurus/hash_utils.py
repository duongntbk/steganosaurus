# -*- coding: utf-8 -*-

'''
Provide hashing function for steganosaurus.
Right now the only supported hashing method is bcrypt.
'''

import base64

import bcrypt
import steganosaurus.constants as constants


def calculate_hash(password, work_factor):
    '''
    Hash password using bcrypt with given work factor.
    '''

    salt = bcrypt.gensalt(work_factor)
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def verify_hash(password, hash):
    '''
    Verify if given password is correct using bcrypt hash.
    '''

    return hash == bcrypt.hashpw(password.encode(), hash)
