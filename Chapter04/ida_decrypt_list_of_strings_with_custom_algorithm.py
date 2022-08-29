from idc import *
from idaapi import *


def decrypt_str(content):
    result = ""
    for val in content:
        val = chr((ord(val) - 1) & 0xFF)
        result += val
    return result


def read_bytes_until_zero(ea):
    result = ""
    for i in range(0xFFFF):
        val = Byte(ea + i)
        if (val) == 0:
            break
        result += chr(val)
    return result


def patch_bytes(ea, buf, size):
    for i in range(size):
        PatchByte(ea, ord(buf[i]))
        ea += 1


def decrypt_all():
    start = ScreenEA()
    size = int(AskStr("1", "Enter the size of the list (in hex)"), 16)
    for ea in range(start, start + size*4, 4):
        decr_str = decrypt_str(read_bytes_until_zero(Dword(ea)))
        print(decr_str)
        patch_bytes(Dword(ea), decr_str, len(decr_str))
        MakeUnknown(Dword(ea), len(decr_str), DOUNK_SIMPLE)
        MakeStr(Dword(ea), BADADDR)


CompileLine('static _decrypt_all() {RunPythonStatement("decrypt_all()");}')
AddHotkey("z", "_decrypt_all")
