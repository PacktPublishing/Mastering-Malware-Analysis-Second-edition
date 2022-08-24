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
        val = get_byte(ea + i)
        if (val) == 0:
            break
        result += chr(val)
    return result


def patch_bytes(ea, buf, size):
    for i in range(size):
        patch_byte(ea, ord(buf[i]))
        ea += 1


def decrypt_all():
    start = get_screen_ea()
    size = int(ask_str("1", 3, "Enter the size of the list (in hex)"), 16)
    for ea in range(start, start + size*8, 8):
        decr_str = decrypt_str(read_bytes_until_zero(get_qword(ea)))
        print(decr_str)
        patch_bytes(get_qword(ea), decr_str, len(decr_str))
        create_strlit(get_qword(ea), 0, STRTYPE_C)


compile_idc_text('static _decrypt_all() {RunPythonStatement("decrypt_all()");}')
add_idc_hotkey("z", "_decrypt_all")
