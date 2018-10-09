import binascii
import struct
import random
import pyshark
import string
from hypothesis.strategies import text
from modules.utils import convert


def mutate_mms_domainId(domainId):
    '''
    5% chance to change to random 3-10 byte value
    5% chance to change to string from hypothesis
    data = F201CTRL
    return value: b')\x00'
    '''
    s = domainId
    if random.random() < 0.05: #5% chance
        s = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(3, 10)))
    elif random.random() < 0.05:
        s = text().example()
        if s is None:
            s = domainId
    return s.encode()

def mutate_mms_itemid(itemid):
    '''
    Mutate the mms attribute itemid change the FC and the split element $
    adds at rendom position split elements. Change ement parts to random byte_str
    itemid = f.i.  B741GGIO3$DC$NamPlt$vendor
    return = LLN0$DC$NamPlt$swRev$ byte encodedt
    '''
    fragmentarray = itemid.split('$')
    if len(fragmentarray) >= 3:
        ln = fragmentarray[0]
        fc = fragmentarray[1]
        do = fragmentarray[2]
        da = fragmentarray[3]
    else:
        return itemid.encode()
    #for lement with more stages
    appstring = '$'
    for ele in fragmentarray[4:]:
        appstring = appstring + str(ele) + '$'
    appstring = appstring[:len(appstring)] #remove last $
    if random.random() < 0.05: #10% chance
        ln = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    fill_elemnt = '$'
    if random.random() < 0.05: #5% choice
        fill_elemnt = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(1))
    fcs = ['MX','ST','CO','CF','DC','SP','SG','RP','LG','BR','GO','GS','SV','SE','MS','US','EX', 'SR', 'OR', 'BL']
    fc_choice = random.random()
    if 0.0 <= fc_choice <= 0.3:
        fc = random.choice(fcs)
    elif 0.4 <= fc_choice <= 0.5:
        fc = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(2))

    if random.random() < 0.05: #5% chance
        #change do to a random 3-10 place string
        do = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(3, 10)))
    if random.random() < 0.05: #5% chance
        #change do to a random 2-10 place string
        da = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(2, 10)))

    id_string = ln + fill_elemnt + fc +fill_elemnt +do + fill_elemnt + da + appstring
    #füge fc an blibiger Stelle ein
    if random.random() < 0.05: #15% chance
        insert_position = random.randint(0, len(id_string))
        id_string = id_string[:insert_position] + fill_elemnt + id_string[insert_position:]
    ret = id_string.encode()
    return ret
