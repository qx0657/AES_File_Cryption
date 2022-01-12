#!/usr/bin/python3

from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import getopt
import sys
import ntpath


class Encryptor:
    def __init__(self, k):
        self.key = k.encode("utf-8")

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, k, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(k, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, ciphertext, k):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(k, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def encrypt_file(self, file_name):
        realpath = os.path.realpath(file_name)
        with open(realpath, 'rb') as fo:
            plaintext = fo.read()
        enc_data = self.encrypt(plaintext, self.key)
        with open(realpath + ".enc", 'wb') as fo:
            fo.write(enc_data)
        os.remove(realpath)

    def encrypt_file_or_dir(self, file_name):
        realpath = os.path.realpath(file_name)
        if os.path.isdir(realpath):
            for dirName, subdirList, fileList in os.walk(realpath):
                for fname in fileList:
                    filetemp = dirName + "\\" + fname
                    if not fname.endswith(".enc") and filetemp != os.path.realpath(sys.argv[0]):
                        print("Encrypt " + filetemp)
                        self.encrypt_file(filetemp)
        else:
            self.encrypt_file(realpath)

    def decrypt_file(self, file_name):
        realpath = os.path.realpath(file_name)
        with open(realpath, 'rb') as fo:
            ciphertext = fo.read()
        dec_data = self.decrypt(ciphertext, self.key)
        with open(realpath[:-4], 'wb') as fo:
            fo.write(dec_data)
        os.remove(realpath)

    def decrypt_file_or_dir(self, file_name):
        realpath = os.path.realpath(file_name)
        if os.path.isdir(realpath):
            for dirName, subdirList, fileList in os.walk(realpath):
                for fname in fileList:
                    filetemp = dirName + "\\" + fname
                    if fname.endswith(".enc"):
                        print("Decrypt " + filetemp)
                        self.decrypt_file(filetemp)
        else:
            self.decrypt_file(realpath)


clear = lambda: os.system('cls')


def input_key():
    while True:
        k = input("key: ")
        if k is None or len(k) == 0:
            continue
        if len(k) > 16:
            k = k[:16]
        else:
            k = k.ljust(16, '0')
        return k


def menu():
    while True:
        clear()
        choice = int(input(
            "1. Press '1' to encrypt.\n2. Press '2' to decrypt.\n3. Press '3' to exit.\n"))
        clear()
        if choice == 1:
            key = input_key()
            enc = Encryptor(key)
            enc.encrypt_file_or_dir(str(input("Enter file or dir to encrypt: ")))
        elif choice == 2:
            key = input_key()
            enc = Encryptor(key)
            enc.decrypt_file_or_dir(str(input("Enter file or dir to decrypt: ")))
        elif choice == 3:
            exit()
        else:
            print("Please select a valid option!")


if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "e:d:hv", ["encrypt", "decrypt", "help", "version"])
    if len(opts) == 0:
        menu()
    else:
        direct = 0
        filename = ''
        for o, a in opts:
            if o in ("-e", "--encrypt"):
                direct = 1
                filename = a
                if filename == None:
                    filename = "./"
            if o in ("-d", "--decrypt"):
                direct = 0
                filename = a
                if filename == None:
                    filename = "./"
            if o in ("-h", "--help"):
                me = ntpath.basename(os.path.realpath(sys.argv[0]))
                print("usage: " + me + " [-e|-d] [file or dir]")
                sys.exit(0)
            if o in ("-v", "--version"):
                print("V.1.1\nBy QianXiao")
                sys.exit(0)
        if direct:
            key = input_key()
            enc = Encryptor(key)
            enc.encrypt_file_or_dir(filename)
        else:
            key = input_key()
            enc = Encryptor(key)
            enc.decrypt_file_or_dir(filename)
