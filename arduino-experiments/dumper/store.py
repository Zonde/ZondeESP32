"""
Reads raw payloads from the ESP32 (which runs the dump sketch)

Author: Daan de Graaf
"""

import serial
import struct

ser = serial.Serial('/dev/ttyUSB0', 115200)


def main():
    dump_count = 0
    while True:
        l = ser.readline()
        if l == b"<<START>>\r\n":
            break
        else:
            print("Ignoring line: {}".format(l))

    while True:
        length, = struct.unpack("<I", ser.read(4))
        packet = ser.read(length)
        with open('dumps/pkt-{}.bin'.format(dump_count), 'wb') as dump_file:
            dump_file.write(packet)
            print("Packet {} of length {} saved".format(dump_count, length))
            dump_count += 1


try:
    main()
finally:
    ser.close()
