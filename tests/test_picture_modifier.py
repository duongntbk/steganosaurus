# -*- coding: utf-8 -*-

"""
Tests for picture_modifier.
"""

import os

import pytest
import steganosaurus.constants as constants
from bitarray import bitarray
from PIL import Image
from steganosaurus.picture_modifier import PictureModifier


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'medium.bmp')
test_data_width = 1087
test_data_height = 1068
test_depth = 2
with open(test_data_path, "rb") as f:
    medium_data = f.read()


def test_init():
    '''
    Can initialize ste_lvl, img and curr_read/write_pixel_index.
    '''

    pm = PictureModifier()
    assert pm.ste_lvl == constants.DEFAULT_STEGANOGRAPHY_LEVEL

    for ste_lvl in range(1, 9):
        pm = PictureModifier(ste_lvl)
        assert pm.ste_lvl == ste_lvl \
            and pm.curr_write_pixel_index == 0 \
            and pm.curr_read_pixel_index == 0 \
            and pm.img is None and pm.pixels is None \
            and pm.img_width == 0 and pm.img_height == 0


def test_init_error_level_value():
    '''
    If steganography level is smaller than 1 or bigger than 0, raise ValueError.
    '''

    ste_lvl_list = [
        0,
        -1,
        9,
        1000
    ]

    for ste_lvl in ste_lvl_list:
        with pytest.raises(ValueError) as ve:
            PictureModifier(ste_lvl)
        assert str(ve.value) == constants.STEGANOGRAPHY_LEVEL_VALUE_ERROR_MSG


def test_init_error_type_value():
    '''
    If steganography level is not a number raise TypeError.
    '''

    ste_lvl_list = [
        'aaa',
        [],
        None
    ]

    for ste_lvl in ste_lvl_list:
        with pytest.raises(TypeError) as te:
            PictureModifier(ste_lvl)
        assert str(te.value) == constants.STEGANOGRAPHY_LEVEL_TYPE_ERROR_MSG


def test_load_medium():
    '''
    Can load picture from binary data.
    '''

    pm = PictureModifier()
    pm.load_medium(medium_data)
    assert pm.img.mode == 'RGB'
    assert pm.img_height == test_data_height
    assert pm.img_width == test_data_width
    assert pm.pixels is not None


def test_export_medium():
    '''
    Can export binary data of medium
    '''

    pm = PictureModifier()
    pm.load_medium(medium_data)
    assert pm.export_medium('BMP') == medium_data


def test_hide_data():
    '''
    Can hide data into low-bit of pixel in image.
    '''

    data = bytes.fromhex('05')
    pm = PictureModifier()
    pm.load_medium(medium_data)

    pm.hide_data(data)

    pixel1 = pm.pixels[0, 0]
    assert __get_bit(pixel1[0], 0) == False
    assert __get_bit(pixel1[0], 1) == False
    assert __get_bit(pixel1[1], 0) == False
    assert __get_bit(pixel1[1], 1) == False
    assert __get_bit(pixel1[2], 0) == False
    assert __get_bit(pixel1[2], 1) == True

    pixel2 = pm.pixels[1, 0]
    assert __get_bit(pixel2[0], 0) == False
    assert __get_bit(pixel2[0], 1) == True


def test_hide_data_picture_not_load():
    '''
    If medium is not loaded, raise ValueError.
    '''

    secret = os.urandom(100)
    pm = PictureModifier()

    with pytest.raises(ValueError) as ve:
        pm.hide_data(secret)
    assert str(ve.value) == constants.PICTURE_NOT_LOADED_ERROR_MSG


def test_hide_data_type_error():
    '''
    If data is not bytes, raise TypeError.
    '''

    data_list = [
        'string',
        [],
        1,
        None
    ]

    pm = PictureModifier()
    pm.load_medium(medium_data)

    for data in data_list:
        with pytest.raises(TypeError) as te:
            pm.hide_data(data)
        assert str(te.value) == constants.INPUT_DATA_ERROR_MSG


def test_hide_data_size_error():
    '''
    If data is too big, raise ValueError
    '''

    data = bytes(b'\0' * int(test_data_width * test_data_height * constants.MAX_COLOR_INDEX * test_depth / 8 + 1))

    pm = PictureModifier()
    pm.load_medium(medium_data)

    with pytest.raises(ValueError) as ve:
        pm.hide_data(data)
    assert str(ve.value) == constants.DATA_SIZE_ERROR_MSG


def test_hide_data_into_pixel():
    '''
    Can hide data into low-bit of individual pixel
    '''

    data = bitarray([True, False, False, False, True])
    pm = PictureModifier()
    pm.load_medium(medium_data)

    pm.hide_data_into_pixel(data)
    assert pm.curr_write_pixel_index == 1

    pixel = pm.pixels[0, 0]
    assert __get_bit(pixel[0], 0) == True
    assert __get_bit(pixel[0], 1) == False
    assert __get_bit(pixel[1], 0) == False
    assert __get_bit(pixel[1], 1) == False
    assert __get_bit(pixel[2], 0) == True


def test_get_data():
    '''
    Can get data from low-bit of pixel in image.
    '''

    data_list1 = [
        bytes.fromhex('ca'),
        os.urandom(100),
        os.urandom(200),
        os.urandom(400),
    ]

    data_list2 = [
        bytes.fromhex('fe'),
        os.urandom(400),
        os.urandom(200),
        os.urandom(100),
    ]

    data_list3 = [
        bytes.fromhex('babe'),
        os.urandom(100),
        os.urandom(200),
        os.urandom(400),
    ]

    data_list4 = [
        os.urandom(100),
        os.urandom(100),
        os.urandom(100),
        os.urandom(100),
    ]

    for data1, data2, data3, data4 in zip(data_list1, data_list2, data_list3, data_list4):
        pm = PictureModifier()
        pm.load_medium(medium_data)

        pm.hide_data(data1)
        pm.hide_data(data2)
        pm.hide_data(data3)
        pm.hide_data(data4)
        assert pm.get_data(len(data1)) == data1
        assert pm.get_data(len(data2)) == data2
        assert pm.get_data(len(data3)) == data3
        assert pm.get_data(len(data4)) == data4


def test_get_data_type_error():
    '''
    If size is not integer, raise TypeError.
    '''

    sizes = [
        None,
        {},
        1
    ]

    pm = PictureModifier()
    pm.load_medium(medium_data)

    for size in zip(sizes):
        with pytest.raises(TypeError) as te:
            pm.get_data(size)
        assert str(te.value) == constants.GET_DATA_PARA_TYPE_ERROR_MSG


def test_get_data_picture_not_load():
    '''
    If medium is not loaded, raise ValueError.
    '''

    pm = PictureModifier()

    with pytest.raises(ValueError) as ve:
        pm.get_data(1)
    assert str(ve.value) == constants.PICTURE_NOT_LOADED_ERROR_MSG


def test_get_data_value_error():
    '''
    If size is bigger than size of medium, raise TypeError
    '''

    sizes = [
        test_data_width * test_data_height * constants.MAX_COLOR_INDEX * test_depth,
        test_data_width * test_data_height * constants.MAX_COLOR_INDEX * test_depth,
        0,
        -1,
        -10
    ]

    messages = [
        constants.GET_DATA_PARA_VALUE_ERROR_MSG,
        constants.GET_DATA_PARA_VALUE_ERROR_MSG,
        constants.GET_DATA_PARA_VALUE_NEGATIVE_MSG,
        constants.GET_DATA_PARA_VALUE_NEGATIVE_MSG,
    ]

    pm = PictureModifier()
    pm.load_medium(medium_data)

    for size, message in zip(sizes, messages):
        with pytest.raises(ValueError) as ve:
            pm.get_data(size)
        assert str(ve.value) == message


def test_get_data_from_pixel():
    '''
    Can get data from low-bit of individual pixel.
    '''

    data1 = bitarray([True, False, False, False , True])
    data2 = bitarray([False, False, False , True, True, True])
    data3 = bitarray([False, False, True, True, True])

    pm = PictureModifier()
    pm.load_medium(medium_data)

    assert pm.curr_write_pixel_index == 0
    pm.hide_data_into_pixel(data1)
    pm.hide_data_into_pixel(data2)
    pm.hide_data_into_pixel(data3)
    assert pm.curr_write_pixel_index == 3

    assert pm.get_data_from_pixel(pm.pixels[0, 0], 5) == data1
    assert pm.get_data_from_pixel(pm.pixels[1, 0], 6) == data2
    assert pm.get_data_from_pixel(pm.pixels[2, 0], 5) == data3


def __get_bit(val, offset):
    '''
    Get value of bit at offset from val.
    This is a helper method, only used within this class.
    '''

    mask = 1 << offset
    return (val & mask) >> offset