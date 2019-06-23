from optparse import OptionParser
from os import listdir
from os.path import isfile, join
import pyshark
import time
import fnmatch
import struct
import subprocess
import sys
import atexit
import traceback
from modules.mutate import tpkt, package
from modules.mutate import mms as mumms
from modules.utils import convert
from modules.connect import connect
from modules.report.report import report

rp = None
associa = None
sgcb = None
sbowes = None
directwes = None
sbowns = None
directwns = None
singlewrite = None
debug = None


def exit_handler():
    global rp
    print('---Fuzzer Stopped!---')
    rp.save_report()
    sys.exit()


def sorte_files_to_category(directory_path):
    """
    sort files to difrent catogeries, direct controll sbow etc.
    connects to an MMS server
    :type directory_path: STRING
    :param directory_path: path to all pcap file
    """
    global associa
    global sgcb
    global sbowes
    global directwes
    global sbowns
    global directwns
    global singlewrite

    files = listdir(directory_path)
    for fil in files:

        words = str(fil).split("_")  # Split topics

        if len(words) > 2:
            if words[1] == '01':  # Single write
                singlewrite.append(fil)
            elif words[1] == '11':
                directwns.append(fil)
            elif words[1] == '12':
                sbowns.append(fil)
            elif words[1] == '13':
                directwes.append(fil)
            elif words[1] == '14':
                sbowes.append(fil)
            elif words[1] == '20':
                sgcb.append(fil)
            elif words[1] == '00':
                if fnmatch.fnmatch(fil, '*associat*'):
                    associa = fil


def test_procedur(type, pkg, count):
    """
    sort files to difrent catogeries, direct controll sbow etc.
    connects to an MMS server
    :type directory_path: STRING
    :param directory_path: path to all pcap file
    """
    global rp
    global debug
    notabort = True
    bytes_to_send = None
    for i in range(count):
        if i % 1000 == 0:
            time.sleep(0.01)
            print('Anzahl:  {}'.format(i))
            # print(subprocess.check_output(['say','und weiter gehts']))
        # time.sleep(0.01) #0.2 ok
        try:
            # time.sleep(0.1) #0.2 ok
            print('.', sep=' ', end='', flush=True)
            if notabort:
                if type == 1:
                    bytes_to_send = package.mutate('01', pkg[0], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                elif type == 11:  # direct w normal security
                    bytes_to_send = package.mutate('11', pkg[0], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                elif type == 12:  # sbo w normal security
                    bytes_to_send = package.mutate('12', pkg[0], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                    time.sleep(0.6)
                    bytes_to_send = package.mutate('12', pkg[1], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                    # send Cancel
                    connect.send_package(convert.pcap_to_stream(pkg[2].tcp.payload))
                elif type == 13:  # direct w e security
                    bytes_to_send = package.mutate('13', pkg[0], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                elif type == 14:  # sbo w e security
                    bytes_to_send = package.mutate('14', pkg[0], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                    time.sleep(0.6)
                    bytes_to_send = package.mutate('14', pkg[1], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                    # send Cancel
                    connect.send_package(convert.pcap_to_stream(pkg[2].tcp.payload))
                elif type == 20:  # SGCB
                    # bytes_to_send = package.mutate('20',pkg[0],debug=debug)
                    bytes_to_send = convert.pcap_to_stream(pkg[0].tcp.payload)
                    notabort = connect.send_package(bytes_to_send)
                    # time.sleep(0.4)
                    bytes_to_send = package.mutate('20', pkg[1], debug=debug)
                    notabort = connect.send_package(bytes_to_send)
                    # time.sleep(0.1)
                    # bytes_to_send = package.mutate('20',pkg[2],debug=debug)
                    bytes_to_send = convert.pcap_to_stream(pkg[2].tcp.payload)
                    notabort = connect.send_package(bytes_to_send)
            else:
                rp.print_singel_test_summary(i+1, file="", conection='Nein! Verbindung vom Server abgebrochen', payload=bytes_to_send)
                rp.save_report()
                connect.disconnect
                atexit.unregister(exit_handler)
                sys.exit()
        except BrokenPipeError as e:
            print('BrokenPipeError', e)
            rp.print_singel_test_summary(i+1, file="", conection='Nein!', payload=bytes_to_send)
            rp.save_report()
            connect.disconnect
            atexit.unregister(exit_handler)
            sys.exit()
        except ValueError as e:
            print('ValueError', e)
            rp.print_singel_test_summary(i+1, file="", conection='Nein!', payload=bytes_to_send)
            rp.save_report()
            connect.disconnect
            atexit.unregister(exit_handler)
            sys.exit()
        except Exception as e:
            traceback.print_exc()
            print(e)
            # print('TypeError', e)
            print('Unexpected error:    {}'.format(sys.exc_info()))
            rp.print_singel_test_summary(i+1, file="", conection='Nein!', payload=bytes_to_send)
            rp.save_report()
            atexit.unregister(exit_handler)
            sys.exit()



def main():
    global associa
    global sgcb
    global sbowes
    global directwes
    global sbowns
    global directwns
    global singlewrite
    global rp
    global debug
    parser = OptionParser()
    parser.add_option(
            "-f", "--file", dest="filedirector",action="store",
            type="string",help="Directory to the .pcap Fieles to fuzz",
            metavar="FILE")

    parser.add_option(
            "-o", "--out", dest="outdirectory",action="store", type="string",
            help="Directory to the result directory", metavar="FILE")

    parser.add_option(
            "-i", "--ipaddress", dest="ip",action="store", type="string",
            help="ip-Address of the IEC61850 Server IED", metavar="FILE")
    parser.add_option(
            "-c", "--count", dest="count",action="store", type="int",
            help="Count of Fuzzing operations of each file default = 500", metavar="FILE")

    parser.add_option(
            "-d", action="store_true", dest="debug",
            help="Optinal user to activate extended debug output to comand line", metavar="FILE")


    (options, args) = parser.parse_args()

    debug = options.debug
    if options.count is None:
        options.count = 20

    #onlyfiles = [f for f in listdir(options.filedirector) if isfile(join(options.filedirector, f))]
    #print(onlyfiles)
    singlewrite = []
    directwns = []
    sbowns = []
    directwes =[]
    sbowes = []
    sgcb = []
    associa = None

    atexit.register(exit_handler)
    sorte_files_to_category(options.filedirector)

    rp = report(export_path = options.outdirectory)
    rp.print_cover()
    summe = options.count*(len(sgcb) + len(sbowes) + len(directwes) + len(sbowns) + len(directwns) + len(singlewrite))
    files = singlewrite + directwns + sbowns + directwes + sbowes + sgcb
    rp.print_global_summary(summe,files)

    #cap = pyshark.FileCapture(options.filedirector +'/'+str(singlewrite[0]),display_filter='ip.src == 60.12.140.42 && mms')
    #bytes_to_send = package.mutate('01',cap[0], debug=True)

    if associa is None:
        print('kein Associat Step gefunden Programm wird beendet. File muss wie folgt Formatiert sein: 1_00_associat.pcap')
        sys.exit()

    #Connect to Server
    try:
        connect.connect(options.filedirector + '/' + associa,options.ip)
    except:
        print('Unexpected error:    {}'.format(sys.exc_info()))

    cap = pyshark.FileCapture(options.filedirector +'/'+str(associa),display_filter='cotp')
    ip = str(cap[0].ip.src)
    filter = 'ip.src == {} && mms && !mms.initiate_RequestPDU_element'.format(ip)
    print(filter)
    cap.close()
    for swrite in singlewrite:
        cap = pyshark.FileCapture(options.filedirector +'/'+str(swrite),display_filter=filter)
        print('File:    {}'.format(swrite))
        rp.print_package(cap[0],swrite)
        # Send Original package to Server as reference
        connect.send_package(convert.pcap_to_stream(cap[0].tcp.payload))
        test_procedur(1,cap, options.count)
        rp.print_singel_test_summary(options.count, file = swrite ,conection = 'ja')
        cap.close()

    for swrite in directwns:
        cap = pyshark.FileCapture(options.filedirector +'/'+str(swrite),display_filter=filter)
        print('File:    {}'.format(swrite))
        rp.print_package(cap[0],swrite)
        # Send Original package to Server as reference
        connect.send_package(convert.pcap_to_stream(cap[0].tcp.payload))
        test_procedur(11,cap, options.count)
        rp.print_singel_test_summary(options.count, file = swrite ,conection = 'ja')
        cap.close()

    for swrite in sbowns:
        cap = pyshark.FileCapture(options.filedirector +'/'+str(swrite),display_filter=filter)
        print('File:    {}'.format(swrite))
        rp.print_package(cap[0],swrite)
        rp.print_package(cap[1],swrite)

        # Send Original package to Server as reference
        connect.send_package(convert.pcap_to_stream(cap[0].tcp.payload))
        time.sleep(0.6)
        connect.send_package(convert.pcap_to_stream(cap[1].tcp.payload))
        test_procedur(12,cap, options.count)
        rp.print_singel_test_summary(options.count, file = swrite ,conection = 'ja')
        cap.close()
    for swrite in directwes:
        cap = pyshark.FileCapture(options.filedirector +'/'+str(swrite),display_filter=filter)
        print('File:    {}'.format(swrite))
        rp.print_package(cap[0],swrite)
        # Send Original package to Server as reference
        connect.send_package(convert.pcap_to_stream(cap[0].tcp.payload))
        test_procedur(13,cap, options.count)
        rp.print_singel_test_summary(options.count, file = swrite ,conection = 'ja')
        cap.close()
    for swrite in sbowes:
        cap = pyshark.FileCapture(options.filedirector +'/'+str(swrite),display_filter=str(filter))
        print('File:    {}'.format(swrite))
        rp.print_package(cap[0],swrite)
        rp.print_package(cap[1],swrite)

        # Send Original package to Server as reference
        connect.send_package(convert.pcap_to_stream(cap[0].tcp.payload))
        time.sleep(0.6)
        connect.send_package(convert.pcap_to_stream(cap[1].tcp.payload))

        test_procedur(14,cap, options.count)
        rp.print_singel_test_summary(options.count, file = swrite ,conection = 'ja')
        cap.close()
    for swrite in sgcb:
        cap = pyshark.FileCapture(options.filedirector +'/'+str(swrite),display_filter=str(filter))
        rp.print_package(cap[0],swrite)
        rp.print_package(cap[1],swrite)
        rp.print_package(cap[2],swrite)
        # Send Original package to Server as reference
        print('File:    {}'.format(swrite))
        connect.send_package(convert.pcap_to_stream(cap[0].tcp.payload))
        time.sleep(0.6)
        connect.send_package(convert.pcap_to_stream(cap[1].tcp.payload))
        time.sleep(0.6)
        connect.send_package(convert.pcap_to_stream(cap[2].tcp.payload))
        time.sleep(0.6)
        test_procedur(20,cap, options.count)
        rp.print_singel_test_summary(options.count, file = swrite ,conection = 'ja')
        cap.close()

    rp.save_report()
    atexit.unregister(exit_handler)

if __name__ == "__main__":
    main()
