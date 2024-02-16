import random
from math import log
from Asn1 import ASN1

from Crypto.Util.number import inverse, GCD
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import json


def is_prime(num):
    if num == 2:
        return True
    if num % 2 == 0:
        return False
    i = 0
    while i < 100:
        a = random.randint(1, num - 1)
        if pow(a, num - 1, num) != 1:
            return False
        i += 1
    return True


def read(source_path):
    try:
        with open(source_path, "rb") as file:
            content = file.read()
            return content
    except:
        print("Read file error")
        exit(0)


def write(destination, content):
    try:
        with open(destination, "wb") as file:
            file.write(content)
    except:
        print("Destination file error")
        exit(0)


def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


class CryptoSystem:

    def __init__(self, p, q):
        n = 0
        try:
            if is_prime(p) is not True or is_prime(q) is not True:
                raise ValueError
            else:
                self.__p = p
                self.__q = q
                n = self.__p * self.__q
        except ValueError:
            exit('number is not prime')
        self.__euler = (self.__p - 1) * (self.__q - 1)
        while True:
            e = random.randint(1, self.__euler - 1)
            if GCD(self.__euler, e) == 1:
                break
        self.public_key = (n, e)
        self.private_key = inverse(e, self.__euler)
        self.aes_key = get_random_bytes(32)
        self.init_vector = get_random_bytes(16)

    def save_asn1(self, content, alg):
        asn1 = ASN1()
        asn1.add(asn1.code_int, content)
        data, length = asn1.put(asn1.code_sequence)
        asn1.clear()
        data, length = asn1.concat_front(data, length)
        asn1.clear()
        asn1.add(asn1.code_int, self.public_key[1])
        asn1.add(asn1.code_int, self.public_key[0])
        asn1.put(asn1.code_sequence)
        data, length = asn1.concat_front(data, length)
        asn1.clear()
        asn1.add(asn1.code_sequence, "")
        asn1.add(asn1.code_utf_string, "6468")
        asn1.add(asn1.code_byte_string, '0021')
        asn1.concat_front(data, length)
        asn1.put(asn1.code_sequence)
        data, length = asn1.put(asn1.code_set)
        if alg == 1:
            asn1.clear()
            asn1.add(asn1.code_int, bytes_needed(content))
            asn1.add(asn1.code_byte_string, "1082")
            asn1.put(asn1.code_sequence)
            asn1.add(asn1.code_set, "")
            asn1.put(asn1.code_sequence)
            asn1.concat_back(data, length)
        elif alg == 2:
            asn1.clear()
            asn1.add(asn1.code_sequence, "")
            asn1.concat_back(data, length)
        data, _ = asn1.put(asn1.code_sequence)
        return data

    def file_encrypt_aes(self, source_path, des_path):
        content = read(source_path)
        crypt = AES.new(self.aes_key, AES.MODE_CBC, self.init_vector)
        res = crypt.encrypt(pad(content, 16))
        write(des_path, res)

    def file_decrypt_aes(self, source_path, des_path):
        content = read(source_path)
        crypt = AES.new(self.aes_key, AES.MODE_CBC, self.init_vector)
        res = crypt.decrypt(content)
        write(des_path, unpad(res, 16))

    def get_hash(self, source_path):
        content = read(source_path)
        sha_hash = SHA256.new(content)
        return int(sha_hash.hexdigest(), 16)

    def encrypt_rsa(self, content):
        if isinstance(content, bytes):
            content = int.from_bytes(content, "big")
        res = pow(content, self.public_key[1], self.public_key[0])
        return int(res).to_bytes(bytes_needed(int(res)), "big")

    def decrypt_rsa(self, content):
        if isinstance(content, bytes):
            content = int.from_bytes(content, "big")
        res = pow(content, self.private_key, self.public_key[0])
        return int(res).to_bytes(bytes_needed(int(res)), "big")
