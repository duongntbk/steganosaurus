# -*- coding: utf-8 -*-

'''
Test for hash_utils.
'''

import base64

import bcrypt
import pytest
import steganosaurus.hash_utils as hash_utils
import steganosaurus.constants as constants
from _pytest.monkeypatch import MonkeyPatch


monkeypatch = MonkeyPatch()

def test_calculate_hash():
    '''
    Can calculate bcrypt hash of password.
    '''

    salts = [
        bytes.fromhex('2432622430382458533954464d334e525361394a594f4c2e76706a634f'),
        bytes.fromhex('2432622430382454613037774f566c4230396e7a47563953615671494f'),
        bytes.fromhex('24326224303824726b71795166354d566331485869387568317874662e')
    ]

    passwords = [
        'secret',
        '日本語',
        '1234567890qwertyuiop!"#$%&\'()"',
    ]

    hashes = [
        bytes.fromhex('2432622430382458533954464d334e525361394a594f4c2e76706a634f3758376f6e704d4d494e686f4132556f70304b38652f72654a706d7a75572e'),
        bytes.fromhex('2432622430382454613037774f566c4230396e7a47563953615671494f576b315475373871564a394a72304a63504d47544c696737636b416979546d'),
        bytes.fromhex('24326224303824726b71795166354d566331485869387568317874662e4a2f50355065635931372e436365594a624f48624446726c414a305a47692e')
    ]

    for salt, password, hash in zip(salts, passwords, hashes):
        with monkeypatch.context() as m:
            m.setattr(bcrypt, 'gensalt', lambda work_factor: salt)

            # For this test we fix work factor as 8.
            work_factor = 8
            assert hash_utils.calculate_hash(password, work_factor) == hash


def test_verify_hash():
    '''
    Can verify a given password using bcrypt hash.
    '''

    passwords = [
        'secret',
        '日本語',
        '1234567890qwertyuiop!"#$%&\'()"',
        'secret1',
        '日本語1',
        '1234567890qwertyuiop!"#$%&\'()"1',
    ]

    hashes = [
        bytes.fromhex('2432622430382458533954464d334e525361394a594f4c2e76706a634f3758376f6e704d4d494e686f4132556f70304b38652f72654a706d7a75572e'),
        bytes.fromhex('2432622430382454613037774f566c4230396e7a47563953615671494f576b315475373871564a394a72304a63504d47544c696737636b416979546d'),
        bytes.fromhex('24326224303824726b71795166354d566331485869387568317874662e4a2f50355065635931372e436365594a624f48624446726c414a305a47692e'),
        bytes.fromhex('2432622430382458533954464d334e525361394a594f4c2e76706a634f3758376f6e704d4d494e686f4132556f70304b38652f72654a706d7a75572e'),
        bytes.fromhex('2432622430382454613037774f566c4230396e7a47563953615671494f576b315475373871564a394a72304a63504d47544c696737636b416979546d'),
        bytes.fromhex('24326224303824726b71795166354d566331485869387568317874662e4a2f50355065635931372e436365594a624f48624446726c414a305a47692e')
    ]

    results = [
        True,
        True,
        True,
        False,
        False,
        False
    ]

    for password, hash, result in zip(passwords, hashes, results):
        assert hash_utils.verify_hash(password, hash) == result