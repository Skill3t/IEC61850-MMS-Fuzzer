import pyshark
import random
import struct
from anytree import Node, NodeMixin, RenderTree, findall_by_attr, Walker
from hypothesis.strategies import binary

from modules.mutate import tpkt, mms
from modules.utils import convert, extractor
from modules.utils import mmstree

i_invokeid = 128


def mutate(ptype, packet, debug=None):
    if debug is None:
        debug = False
    singele_write = ['01', '11', '13']
    sbo = ['12', '14', '20']
    if ptype in singele_write:  # single singlewrite
        raw_mms = packet.pres.fully_encoded_data.raw_value
        rawtcp = packet.tcp.payload.raw_value
        vormms = rawtcp.split(raw_mms)[0]
        between_tktp_mms = vormms[8:len(vormms)-2]
        bytesbetween = bytes.fromhex(between_tktp_mms)
        partmms = p_mms_tree(ptype, packet, debug)
        parttpkg = tpkt.rebuilt(4+len(bytesbetween) + len(partmms)+1)
        holepackage = parttpkg + bytesbetween + (len(partmms)).to_bytes(1, byteorder='big') + partmms
        return holepackage
    elif ptype in sbo:
        raw_mms = packet.pres.fully_encoded_data.raw_value
        rawtcp = packet.tcp.payload.raw_value
        vormms = rawtcp.split(raw_mms)[0]
        between_tktp_mms = vormms[8:len(vormms)-2]
        bytesbetween = bytes.fromhex(between_tktp_mms)
        partmms = p_mms_tree(ptype, packet, debug)
        parttpkg = tpkt.rebuilt(4+len(bytesbetween) + len(partmms)+1)
        holepackage = parttpkg + bytesbetween + (len(partmms)).to_bytes(1, byteorder='big') + partmms
        return holepackage


def rebuild_tree(leave_element):
    # Durchlauf des Baumens von unten nach oben
    for n in reversed(leave_element.path):
        # wenn element einen parant hat
        if n.parent:
            # Viele kinder
            if len(n.parent.children) > 1:
                n.parent.payload = b''
                n.parent.blength = b''
                n.parent.ilength = int()
                for child in n.parent.children:
                    n.parent.payload = n.parent.payload + child.mmstype + child.blength + child.payload
                    n.parent.blength = (len(n.parent.payload)).to_bytes(1, byteorder='big')
                    n.parent.ilength = len(n.parent.payload)
            # Ein kinder genauer n
            else:
                n.parent.payload = n.mmstype + n.blength + n.payload
                n.parent.blength = (len(n.parent.payload)).to_bytes(1, byteorder='big')
                n.parent.ilength = len(n.parent.payload)


def change_value_node(value):
    '''value is leave tree element return mutatet data in leave tree element
    '''
    if random.random() < 0.9:  # 10% chance
        if value.mmstype == b'\x83':
            # boolean 1
            chance = random.random()
            if chance < 0.45:
                value.payload = b'\x00'  # False
            elif chance > 0.55:
                value.payload = (random.randint(1, 255)).to_bytes(1, byteorder='big')  # True
        elif value.mmstype == b'\x84':
            # quality / CODED ENUM 3 / 2
            return
            if value.ilength == 3:  # quality
                value.payload = (random.randint(0, 16777215)).to_bytes(3, byteorder='big')
            if value.ilength == 2:  # CODED ENUM
                value.payload = (random.randint(0, 65535)).to_bytes(2, byteorder='big')

        elif value.mmstype == b'\x85':
            # int / ENUMERATED 2-9 / 2
            value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
        elif value.mmstype == b'\x86':
            # intU
            value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
        elif value.mmstype == b'\x87':
            # flaot
            value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
        elif value.mmstype == b'\x89':
            if random.random() < 0.1:  # 10% chance
                value.ilength = random.randint(1, 20)
                value.blength = (value.ilength).to_bytes(1, byteorder='big')
                value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
            else:
                # OCTET STRING 20 bytes
                value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
        elif value.mmstype == b'\x8a':
            if random.random() < 0.1:  # 10% chance
                value.ilength = random.randint(1, 35)
                value.blength = (value.ilength).to_bytes(1, byteorder='big')
                value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
            else:
                # VISIBLE STRING 35 bytes
                value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
        elif value.mmstype == b'\xa0':
            if random.random() < 0.1:  # 10% chance
                value.ilength = random.randint(1, 35)
                value.blength = (value.ilength).to_bytes(1, byteorder='big')
                value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
            else:
                # VISIBLE STRING 35 bytes
                value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')
        elif value.mmstype == b'\x91':
            # TimeStamp 8bytes
            value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')  # True
        else:
            print('error unknown basetype, basetype:    {}'.format(value.mmstype))
            value.payload = (random.randint(0, (256**value.ilength)-1)).to_bytes(value.ilength, byteorder='big')  # True
        if random.random() < 0.1:  # 10% chance
            randmmstype = [b'\x83'b'\x84', b'\x85', b'\x86', b'\x87'b'\x89', b'\x8a', b'\xa0', b'\x91']
            value.mmstype = random.choice(randmmstype)
    else:
        value.payload = b''
        value.blength = (0).to_bytes(1, byteorder='big')
        value.ilength = 0
    rebuild_tree(value)




def print_tree(root):
    '''
    print the tree to the comandline
    '''
    for pre, _, node in RenderTree(root):
        treestr = u"%s%s" % (pre, node.name)
        print(treestr.ljust(8),node.mmstype, node.ilength, node.payload)


def p_mms_tree(ptype, packet, debug):
    global i_invokeid
    raw_value = packet.pres.fully_encoded_data.raw_value
    bytesraw = bytes.fromhex(raw_value)
    root = extractor.extract_mms_structur(bytesraw,len(bytesraw))
    if debug:
        print_tree(root)

    listblatt = findall_by_attr(root, 'blatt')
    if len(listblatt) < 5:
        raise ValueError('at least 1 Data leaf Element needet')
    presentation_context_identifier = listblatt[0]# 1 (mms-abstract-syntax-version1(1))

    invokeid = listblatt[1]
    domainid = listblatt[2]
    itemid = listblatt[3]

    for subvalues in listblatt[4:]:
        change_value_node(subvalues)
    if i_invokeid % 32767 == 0:
        i_invokeid = 128
    i_invokeid += 1
    invokeid.payload = (i_invokeid).to_bytes(2, byteorder='big')
    rebuild_tree(invokeid)
    #domainid.payload.decode('utf-8')
    if random.random() < 0.01: #1% chance
        mutated_domainId = mms.mutate_mms_domainId(domainid.payload.decode('utf-8'))
        if not mutated_domainId is None:
            domainid.payload = mutated_domainId
            domainid.ilength = len(mutated_domainId)
            domainid.blength = (len(mutated_domainId)).to_bytes(1, byteorder='big')
            #rebuild_tree(domainid)

    if random.random() < 0.05: #1% chance
        mutated_itemid = mms.mutate_mms_itemid(itemid.payload.decode('utf-8'))
        itemid.payload = mutated_itemid
        itemid.ilength = len(mutated_itemid)
        itemid.blength = (len(itemid.payload)).to_bytes(1, byteorder='big')
        #komentar hier einfügen
    mms_valid_types = [b'\x80',b'\x81',b'\x83',b'\x84',b'\x85'b'\x86',b'\x87',b'\x88,'b'\x89',b'\x8a',b'\x91',b'\xa0',b'\x1a',b'\xa5',b'\x02']
    #if random.random() < 0.01: #1% chance
    #    itemid.mmstype = random.choice(mms_valid_types)
    #if random.random() < 0.02: #1% chance
    #    lenght = random.randint(0,100)
    #    itemid.ilength = lenght
    #    itemid.blength = (lenght).to_bytes(1, byteorder='big')
    rebuild_tree(itemid)
    if debug:
        print_tree(root)
    return root.payload
