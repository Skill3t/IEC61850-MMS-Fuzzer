import struct
import pyshark


def rebuilt(lenght, version=None, reserved=None):
    '''
    rebuilt the bytes of the tpkt package
    lenght = integer value beween 0 - 65535
    version = optional default b'\x03'
    reserved = optional default b'\x00'
    result = b'\x03' + b'\x00' + lenght in 2 Bytes
    '''
    if version is None:
        version = b'\x03'
    if reserved is None:
        reserved = b'\x00'
    newlength = b'\x00' + b'\x00'
    if int(lenght) > 65535:
        raise ValueError
    elif int(lenght) < 256:
        newlength = b'\x00' + (lenght).to_bytes(1, byteorder='big')
    else:
        newlength = (lenght).to_bytes(2, byteorder='big')
    values = version + reserved + newlength
    return values
