import binascii
import struct
import random

def pcap_to_stream(pcaptoppayload):
    '''
    Funktion takes the pyshark tcp payload and convert the data to send them
    directly to a python tcp socket
    pcaptoppayload = 03:00:00:53:02:f0:80:01:00:01:00:61:46:30:44:02:01:01:a0:
        3f:a0:3d:02:02:28:86:a5:37:a0:30:30:2e:a0:2c:a1:2a:1a:08:46:34:31:30:4d:
        45:41:53:1a:1e:50:32:4d:4d:58:55:31:24:43:46:24:41:24:70:68:73:43:24:75:
        6e:69:74:73:24:53:49:55:6e:69:74:a0:03:85:01:01

    return = b'\x03\x00\x00S\x02\xf0\x80\x01\x00\x01\x00aF0D\x02\x01\x01\xa0?\
    xa0=\x02\x02(\x86\xa57\xa000.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$
    A$phsC$units$SIUnit\xa0\x03\x85\x01\x01'
    '''
    words = pcaptoppayload.split(':')
    bytelis = bytes()
    for b in words:
        bytelis = bytelis + bytes.fromhex(b)
    return bytelis
