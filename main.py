from Crypt import CryptoSystem
import struct

if __name__ == '__main__':

    p = 57896044625259982827082014024491516445703215213774687456785671200359045162371
    q = 28948022312629991413541007012245758222850495633896873081323396140811733708403
    obj = CryptoSystem(p, q)

    print('p: ', p)
    print('q: ', q)
    print('private key: ', obj.private_key)
    print('module: ', obj.public_key[0])
    print('e: ', obj.public_key[1])
    print('aes key: ', int.from_bytes(obj.aes_key, 'big'))

    while 1:
        mode = int(input('1 - Encrypt\n2 - Decrypt\n3 - Signature generation\n4 - Signature verification\n5 - Exit\n'))
        if mode == 5:
            break

        aes_key = obj.encrypt_rsa(obj.aes_key)
        if mode == 1:
            obj.file_encrypt_aes('mine.txt', 'encrypt_mine.txt')

            data = obj.save_asn1(int.from_bytes(aes_key, 'big'), 1)
            data = list(data)
            list_symbol = []
            i = 0
            while i < len(data) - 1:
                c = int(data[i] + data[i + 1], 16)
                list_symbol.append(struct.pack("B", c))
                i += 2

            file = open("file1.dat", "wb")
            for i in list_symbol:
                file.write(i)
            file.close()
        if mode == 2:
            obj.aes_key = obj.decrypt_rsa(aes_key)
            obj.file_decrypt_aes('encrypt_mine.txt', 'decrypt_mine.txt')
        if mode == 3:
            h = obj.get_hash('mine.txt')
            enc_h = obj.decrypt_rsa(h)
            file = open("signed_file.sig", "wb")
            file.write(enc_h)
            file.close()

            data = obj.save_asn1(int.from_bytes(enc_h, 'big'), 2)
            data = list(data)
            list_symbol = []
            i = 0
            while i < len(data) - 1:
                c = int(data[i] + data[i + 1], 16)
                list_symbol.append(struct.pack("B", c))
                i += 2

            file = open("file2.dat", "wb")
            for i in list_symbol:
                file.write(i)
            file.close()
        if mode == 4:
            h = obj.get_hash('decrypt_mine.txt')
            file = open("signed_file.sig", "rb")
            enc_h = int.from_bytes(obj.encrypt_rsa(file.read()), 'big')
            file.close()

            if h == enc_h:
                print('Signature accepted')
            else:
                print('Signature not accepted')



