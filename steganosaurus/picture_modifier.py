# -*- coding: utf-8 -*-

"""
This module modifies picture to hide data into low-bit position of r, g, b color
"""

import io

import steganosaurus.constants as constants
from bitarray import bitarray
from PIL import Image


class PictureModifier:
    '''
    This class can modify each pixel of picture to hide data.
    '''

    def __init__(self, ste_lvl=constants.DEFAULT_STEGANOGRAPHY_LEVEL):
        '''
        Constructor: 
        + Initialize the number of steganography bit in each byte, max is 8.
        (the higher this value, the more stenography picture will differs from original picture).
        + Initialize object to store original picture.
        + Initialize current read and write offset.
        '''

        if not isinstance(ste_lvl, int):
            raise TypeError(constants.STEGANOGRAPHY_LEVEL_TYPE_ERROR_MSG)

        if ste_lvl < constants.MIN_STEGANOGRAPHY_LEVEL or \
                constants.MAX_STEGANOGRAPHY_LEVEL < ste_lvl:
            raise ValueError(constants.STEGANOGRAPHY_LEVEL_VALUE_ERROR_MSG)

        self.ste_lvl = ste_lvl
        self.curr_write_pixel_index = 0
        self.curr_read_pixel_index = 0
        self.img = None
        self.pixels = None
        self.img_width = 0
        self.img_height = 0

    def load_medium(self, data):
        '''
        Load picture from give path.
        '''

        self.img = Image.open(io.BytesIO(data))
        self.pixels = self.img.load() # Lazy loading.
        self.img_width = self.img.width
        self.img_height = self.img.height

    def export_medium(self, format):
        '''
        Return binary data of medium.
        This method will be called after secret has been hidden into medium.
        '''

        output = io.BytesIO()
        self.img.save(output, format=format)
        return output.getvalue()

    def hide_data(self, data):
        '''
        Hide data into low-bit of pixels.
        '''

        if self.img is None:
            raise ValueError(constants.PICTURE_NOT_LOADED_ERROR_MSG)

        if not isinstance(data, bytes):
            raise TypeError(constants.INPUT_DATA_ERROR_MSG)

        if len(data) * 8 >= self.img_width * self.img_height * constants.MAX_COLOR_INDEX * self.ste_lvl:
            raise ValueError(constants.DATA_SIZE_ERROR_MSG)
        
        bitdata = bitarray()
        bitdata.frombytes(data)
        bit_per_pixel = constants.MAX_COLOR_INDEX * self.ste_lvl
        for i in range(0, len(bitdata), bit_per_pixel):
            self.hide_data_into_pixel(bitdata[i:i+bit_per_pixel]) # No index out-of-range risk because of python magic.

    def hide_data_into_pixel(self, data):
        '''
        Hide data into low-bit of 1 individual pixel.
        '''

        i_height = self.curr_write_pixel_index // self.img_width
        i_width = self.curr_write_pixel_index - self.img_width * i_height
        color = list(self.pixels[i_width, i_height])
        color_index = 0
        depth_index = 0

        for bit in data:
            if depth_index == self.ste_lvl:
                color_index += 1
                depth_index = 0

            # Inlining bit-wise operation to improve performance.
            mask = 1 << depth_index
            color[color_index] &= ~mask
            if bit:
                color[color_index] |= mask
            depth_index += 1

        self.pixels[i_width, i_height] = tuple(color)
        self.curr_write_pixel_index += 1

    def get_data(self, size):
        '''
        Get data from low-bit of pixel.
        Unit of return data and offset is bytes.
        '''

        if self.img is None:
            raise ValueError(constants.PICTURE_NOT_LOADED_ERROR_MSG)

        if not isinstance(size, int):
            raise TypeError(constants.GET_DATA_PARA_TYPE_ERROR_MSG)

        if size <= 0:
            raise ValueError(constants.GET_DATA_PARA_VALUE_NEGATIVE_MSG)

        if self.img_width * self.img_height * constants.MAX_COLOR_INDEX * self.ste_lvl <= size * 8:
            raise ValueError(constants.GET_DATA_PARA_VALUE_ERROR_MSG)

        b_arr = bitarray()
        pixel_bit_capacity = constants.MAX_COLOR_INDEX * self.ste_lvl

        for index in range(0, size * 8, pixel_bit_capacity):
            i_height = self.curr_read_pixel_index // self.img_width
            i_width = self.curr_read_pixel_index - self.img_width * i_height
            pixel = self.pixels[i_width, i_height]
            bit_count = min(pixel_bit_capacity, size * 8 - index)
            pixel_data = self.get_data_from_pixel(pixel, bit_count)
            b_arr.extend(pixel_data)
            self.curr_read_pixel_index += 1

        return b_arr.tobytes()

    def get_data_from_pixel(self, pixel, size):
        '''
        Get data from low-bit of individual pixel.
        '''

        color_index = 0
        depth_index = 0
        b_arr = bitarray()

        for _ in range(size):
            if depth_index == self.ste_lvl:
                color_index += 1
                depth_index = 0

            # Get value of low-bit from pixel.
            # Inlining this process to improve performance.
            mask = 1 << depth_index
            bit_val = (pixel[color_index] & mask) >> depth_index
            # Add retrived bit to array.
            b_arr.append(bit_val)
            depth_index += 1

        return b_arr
