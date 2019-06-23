import sys

import socket
from socket import AF_INET, SOCK_STREAM
import fcntl, os
import errno
from time import sleep
import pyshark
import traceback
import subprocess

import modules.utils.convert as conv


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.settimeout(15)


def connect(path0_associat, ip=None):
    """
    connects to an MMS server
    :type path0_associat: STRING
    :param path0_associat: path to an pcap file with only an associat captuered

    :type ip: string
    :param ip: ip adress where to connect (adress of the server)
    """
    try:
        cap = pyshark.FileCapture(path0_associat, display_filter='cotp')
    except FileNotFoundError as e:
        raise ValueError('Ungültiger dateipfad zum associat' + str(e))
    if ip is None:
        ip = str(cap[0].ip.dst)
    server_addr = (ip, 102)
    print('server_addr: {}'.format(str(ip)))
    try:
        result = client_socket.connect(server_addr)
        print(result)
    except IOError as e:
        client_socket.close()
        raise ValueError('Fehler beim connect', e)
    client_socket.send(conv.pcap_to_stream(cap[0].tcp.payload))
    data, addr = client_socket.recvfrom(102)
    print("cotp ----------received")
    print("received", data, "from", addr)
    print('payload')
    print(conv.pcap_to_stream(cap[2].tcp.payload))
    client_socket.send(conv.pcap_to_stream(cap[2].tcp.payload))
    data, addr = client_socket.recvfrom(102)
    print("mms associate ----------received")
    print("received: {}, from: {}".format(data, addr))
    return True


def send_package(payload):
    '''
    send payload to the server socket
    payload = bytes
    '''
    if payload is None:
        return True
    else:
        # client_socket.send(payload)
        try:
            client_socket.send(payload)
            data, addr = client_socket.recvfrom(102)
            zerowindow = str(b'\x01\x01\x08\x0a\x1b\x57\x8a\xfe\x02\xe5\x03\x56')
            abort = str(b'\x03\x00\x00\x16\x02\xf0\x80\x19\r\x11\x01\x03\xc1\x080\x06\x80\x01\x05\x81\x01\x07')
            if zerowindow in str(data):
                print("zerowindow")
                print('\a')
                return False
            elif abort in str(data):
                print("ABORT!")
                print('\a')
                return False
            else:
                return True
        except socket.timeout:
            print('\a')
            # print(subprocess.check_output(['say','das sieht nicht gut aus']))
            print('socket.timeout')
            traceback.print_exc()
        except socket.error as err:
            print('socket.erro' + str(err))
            print('\a')
            # print(subprocess.check_output(['say','das sieht nicht gut aus']))
            traceback.print_exc()
        except Exception as e:
            print('\a' + str(e))
            # print(subprocess.check_output(['say','das sieht nicht gut aus']))
            traceback.print_exc()
            disconnect()


def disconnect():
    """
    cloase the TCP Session no abord send
    """
    client_socket.close()
