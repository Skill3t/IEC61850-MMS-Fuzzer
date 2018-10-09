import struct

from modules.utils.mmstree import Tree


def getbytestr(data_byte):
    '''
    converte da 2 digit byte into da string object
    '''
    byte_str = map('{:02x}'.format ,data_byte)
    return ''.join(byte_str)

def extract_mms_structur(raw_value, lengtparent, root=None):
    '''
    Funktion geht an ASN1 encodet data tree as byte object an convert the data
    to an Tree object
    raw_value = b'\x02\x02(\x86\xa57\xa000.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit\xa0\x03\x85'
    return tree
    root     0 0 0
    └── node b'0' 68 b'\x02\x01\x01\xa0?\xa0=\x02\x02(\x86\xa57\xa000.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit\xa0\x03\x85\x01\x01'
        ├── blatt b'\x02' 1 b'\x01'
        └── node b'\xa0' 63 b'\xa0=\x02\x02(\x86\xa57\xa000.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit\xa0\x03\x85\x01\x01'
            └── node b'\xa0' 61 b'\x02\x02(\x86\xa57\xa000.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit\xa0\x03\x85\x01\x01'
                ├── blatt b'\x02' 2 b'(\x86'
                └── node b'\xa5' 55 b'\xa000.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit\xa0\x03\x85\x01\x01'
                    ├── node b'\xa0' 48 b'0.\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit'
                    │   └── node b'0' 46 b'\xa0,\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit'
                    │       └── node b'\xa0' 44 b'\xa1*\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit'
                    │           └── node b'\xa1' 42 b'\x1a\x08F410MEAS\x1a\x1eP2MMXU1$CF$A$phsC$units$SIUnit'
                    │               ├── blatt b'\x1a' 8 b'F410MEAS'
                    │               └── blatt b'\x1a' 30 b'P2MMXU1$CF$A$phsC$units$SIUnit'
                    └── node b'\xa0' 3 b'\x85\x01\x01'
                        └── blatt b'\x85' 1 b'\x01'
    '''
    if root is None:
        root = Tree('root',0,0,0,0)
    mmstypes = {'a0','a1','02','85','83','a5','30','1a','61','a2','86','91','84','89','8a'}
    # none leaves hat lenght
    if len(raw_value) <=1:
        root.name = 'blatt'
        root.payload = raw_value
    else:
        type_mms, länge = struct.unpack('! 1s 1s', raw_value[:2])
        länge_i = int.from_bytes(länge,byteorder='big')
        payload = raw_value[2:2 + länge_i]
        if getbytestr(type_mms) in mmstypes and len(payload) > 0: # >0 for 02 02 02 02 case invoke id = 514 tow leave elements
            node = Tree('node',type_mms,länge,länge_i,payload, root)
            #if lengtparent != länge_i+2:
            if länge_i != len(raw_value)-2:
                #linker knoten
                extract_mms_structur(raw_value[2:2+len(payload)],länge_i,node)
                #rechter knoten
                extract_mms_structur(raw_value[2+len(payload):],lengtparent-länge_i-2,root)
            else:
                #print('Ein kinder enthalten')
                extract_mms_structur(raw_value[2:],länge_i,node)
        elif länge_i == len(raw_value)-2: #case tree with 2 leaves and 1 with zero payload will change in rekusion to leave
            node = Tree('blatt',type_mms,länge,länge_i,payload, root)
            extract_mms_structur(raw_value[2:2+len(payload)],länge_i,node)
        else:
            root.name = 'blatt'
            root.payload = raw_value
        return root
