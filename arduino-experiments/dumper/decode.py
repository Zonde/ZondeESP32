"""
Partial decoder for 802.11 payloads, decodes all files in ./dumps/ as raw binary payload data

Author: Daan de Graaf
"""

import sys
from os import listdir
from os.path import join

def analyse_packet(path):
    data = open(path, 'rb').read()

    type = (data[0] & 0b00001100) >> 2
    if type == 0b00:
        print("Type: Management")
    elif type == 0b01:
        print("Type: Control")
        sys.exit(1)
    else:
        print("Type: UNKNOWN")
        sys.exit(1)

    subtype = (data[0] & 0b11110000) >> 4
    if subtype == 0b0100:
        print("Subtype: Probe request")
    else:
        print("Subtype: Unknown")
        sys.exit(1)

    def fmt_addr(addr):
        return ':'.join('{:02x}'.format(part) for part in addr)

    receiver = data[4:10]
    print("Receiver: {}".format(fmt_addr(receiver)))
    transmitter = data[10:16]
    print("Transmitter: {}".format(fmt_addr(transmitter)))
    bssid = data[16:22]
    print("BSSID: {}".format(fmt_addr(bssid)))

    # Everything besides the frame body is 34 bytes, -4 bytes FCS at the end means the body should start at byte 30. But probe request doesn't use address 4, so the body starts at byte 24
    body = data[24:-4]

    i = 0
    while i < len(body):
        elem_id = body[i]
        length = body[i+1]
        if elem_id == 0:
            print("SSID element found, length: {}".format(length))
            if length > 0:
                ssid = body[i+2:i+2+length]
                print("SSID: {}".format(ssid))
        else:
            pass
            #print("Unknown element of length {} found".format(length))
        i += 2 + length
    print()

dumps = listdir('dumps')
for dump in dumps:
    path = join('dumps', dump)
    analyse_packet(path)
