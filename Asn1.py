from math import log


def size(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def get_length(byte):
    byte = int(byte, 16)
    bit = format(byte, '08b')
    if bit[0] == '1':
        return int(bit[1:8], 2)
    else:
        return 0


def length_converter(length):
    if length < 128:
        return format(length, '02x')
    else:
        size_of_length = format(int('1' + format(size(length), '07b'), 2), '02x')
        formatter = '0' + str(size(length) * 2) + 'x'
        return size_of_length + format(length, formatter)


class ASN1:
    def __init__(self):
        self.code_int = "02"
        self.code_utf_string = "0c"
        self.code_byte_string = "04"
        self.code_sequence = "30"
        self.code_set = "31"
        self.length = 0
        self.result = ""

    def concat_front(self, data, length):
        self.result += data
        self.length += length
        return self.result, self.length

    def concat_back(self, data, length):
        self.result = data + self.result
        self.length += length
        return self.result, self.length

    def clear(self):
        self.length = 0
        self.result = ""

    def put(self, code):
        self.result = code + length_converter(self.length) + self.result
        self.length += get_length(length_converter(self.length)) + 2
        return self.result, self.length

    def add(self, code, parameter):
        par = ""
        sz = 0
        if isinstance(parameter, int):
            self.length += get_length(length_converter(self.length)) + 1 + size(parameter) + 1
            formatter = '0' + str(size(parameter) * 2) + 'x'
            par = format(parameter, formatter)
            sz = size(parameter)
        elif isinstance(parameter, str):
            self.length += len(parameter) // 2 + 1 + size(len(parameter) // 2)
            par = parameter
            sz = len(parameter) // 2
        self.result = code + length_converter(sz) + par + self.result
        return self.result, self.length