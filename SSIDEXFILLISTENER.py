#!/usr/bin/python3

# SSIDExfil Listener by Nick Paul and AJ Lopez
# Platform : Linux/Windows
# ------------------------------------------------------------------------------------------------
# Reads a captured .pcap file and reconstructs data exfiltrated via SSIDExfil.
# Extracts marked probe request SSIDs, reassembles the chunks, and decompresses the data.
# ------------------------------------------------------------------------------------------------
# Usage: echo "/path/to/capture.pcap" | python SSIDEXFILLISTENER.py

import sys
import re
import zlib
from codecs import encode
from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt


# Must match the START_CHAR used in SSIDEXFIL.py
START_CHAR = '*'


def getData(packets):
    """Extract all exfiltration SSIDs from packet capture (deduped, in order)."""
    compressedData = []
    for packet in packets:
        try:
            ssid = packet.getlayer(Dot11Elt).info.decode('utf-8')
            if re.match('^[' + re.escape(START_CHAR) + ']', ssid):
                if ssid not in compressedData:
                    compressedData.append(ssid)
        except Exception:
            # Packet has no SSID info field — skip
            pass
    return compressedData


def decompressData(compressedData):
    """Strip the prefix character from each chunk, reassemble, and decompress."""
    chunks = []
    for piece in compressedData:
        # Remove the leading start character and surrounding artifact bytes
        tmp = list(piece)
        tmp[0] = ''
        tmp[1] = ''
        tmp[2] = ''
        tmp[-1] = ''
        chunks.append(''.join(tmp))

    joined = ''.join(chunks)
    raw = encode(joined.encode().decode('unicode_escape'), 'raw_unicode_escape')
    return zlib.decompress(raw)


if __name__ == '__main__':

    pcapPath = sys.stdin.read().strip()

    if not pcapPath:
        print('[-] No pcap path provided. Usage: echo "/path/to/capture.pcap" | python SSIDEXFILLISTENER.py')
        sys.exit(1)

    print('[+] Reading capture file: {}'.format(pcapPath))
    packets = rdpcap(pcapPath)

    print('[+] Extracting exfiltration SSIDs...')
    compressedData = getData(packets)
    print('[+] Found {} exfiltration chunks.'.format(len(compressedData)))

    if not compressedData:
        print('[-] No exfiltration data found in capture.')
        sys.exit(1)

    print('[+] Decompressing and reassembling data...')
    data = decompressData(compressedData)

    outputFile = 'exfiltratedData.txt'
    with open(outputFile, 'wb') as f:
        f.write(data)

    print('[+] Data written to {}'.format(outputFile))
