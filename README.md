IEC61850-MMS-Fuzzer
==================

## Overview

Mutation Based Fuzzer. Test your IEC61850 MMS Server Implementations.
Mutation Based means in this context that the inputs have to do be genrated separately. The previously recorded network traffic has to be split 
in little chunks. The input data needs to have the following datanames. 

Format: X_YY_ZZ.pcap
X: sequential number. YY: coding of the service:
- 00 Association
- 01 Write value
- 11 Direct control with normal security
- 12 SBO control with normal security
- 13 Direct control with enhanced security
- 14 SBO control with enhanced security
- 20 SGCB
- ZZ: Logical node reference.

### Input filter:
Use Wireshark Filter ip.src == (server ip) && mms
- 01: Use first package
- 11: Use first package
- 12: Use first and second package (first select, second control)
- 13: Use first and second package (first select, second control) enhanced security is just for the client relevant but not for Fuzzing
- 20: Use first, second and third package (edit SG, write single Data, confirm edit SG)

## Features
- Association
- Mutation of data 
- Resend the mutated data (over a TCP-Socked)
- Generate PDF documentation of the tests

## Parameter
- Python main.py -h
- f: Directory of the input data
- i: IP-Adress of the server
- o: Path to the documentation directory (output for the PDF documentation)
- c: Count number of tests (mutations) of each input file (default 500)
- d: Debug (default false)

example: python main.py -f /Users/XZ/... -i 192.168.1.42 -c 200 –d



### Used IEC61850 services
- Associate
- Release
- SelectEditSG
- SetEditSGValue
- ConfirmEditSGValues - Select
- SelectWithValue
- Operate
- Write

## Requirements
- Python 3.X
- Pyshark
- Anytree
- Reportlab
- ...
- Pip install -r requirements.txt

## Info
- please feel free to send a pull request
- no warranty 
- please only use laboratory environment and handle all findings responible


## License
- CDDL


