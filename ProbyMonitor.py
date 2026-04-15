#!/usr/bin/python3

# ProbyMonitor by Nick Paul and AJ Lopez
# Platform : Linux (Tested on Parrot OS and Kali)
# ------------------------------------------------------------------------------------------------
# A tool that aims to detect possible data exfiltration through monitoring 802.11 probe requests
# ------------------------------------------------------------------------------------------------
# Sets network interface into monitor mode
# Listens for 802.11 probe requests
# Filter out legitimate probe requests and bogus ones
# Prints results


from scapy.all import get_if_list, sniff
from scapy.layers.dot11 import *
import scapy
import os
import subprocess
import time
import wifi
import sys

splashArt = """
╔═╗┬─┐┌─┐┌┐ ┬ ┬╔╦╗┌─┐┌┐┌┬┌┬┐┌─┐┬─┐
╠═╝├┬┘│ │├┴┐└┬┘║║║│ │││││ │ │ │├┬┘
╩  ┴└─└─┘└─┘ ┴ ╩ ╩└─┘┘└┘┴ ┴ └─┘┴└─ 
by Nick Paul and AJ Lopez                                                                                                                                                        
"""

#The following holds all global variables needed
specifiedInterface = None
airmonInterface = None
detectedAPS = []
allProbes = []
totalCapturedProbes = 0
countsOfProbes = {}


#The following will prompt the user to select the interface to monior traffic on
#It will take the specified interface and generate a list of nearby access points
#It will also put the network interface into monitor mode via airmon-ng
def specifyInterface():

    global specifiedInterface 
    global airmonInterface
    global detectedAPS

    #Lists all interfaces avaliable and allows user to select which one they wish to use
    print('[+] Interfaces avaliable on this system: ')
    interfaceList = get_if_list()
    while True:
        if specifiedInterface in interfaceList: break
        for x in interfaceList: print('\t-' + x)
        specifiedInterface = input('\n[+] Please enter a valid interface to monitor traffic on: ')

    #Scan for nearby Access Points using the package wifi and stores them in variable
    print('[+] Generating list of neaby access points. . . please wait. . .')
    tmpAPS = wifi.Cell.all(specifiedInterface)
    for x in tmpAPS:
        detectedAPS.append(x.ssid)
    time.sleep(4)


    #Puts the specified interface into monitor mode
    try:
        #Run shell command to put specified interface into monitor mode
        print ('[+] Putting ' + specifiedInterface + ' into monitor mode. . .')
        subprocess.Popen(["airmon-ng","start", specifiedInterface],stdout=subprocess.PIPE)
        time.sleep(3)
        #Assign monitor interface as new specifedInterface
        if specifiedInterface + 'mon' in get_if_list():
            specifiedInterface = specifiedInterface + 'mon'

    except Exception as e:
        print('[-] Error putting interface into monitor mode: ' + str(e))
        exit(1)

def updateCount():
    print('Starting')
    while True:
        global totalCapturedProbes
        print ('Total captured probes: ' + totalCapturedProbes)
        time.sleep(5)

#This function will take in a packet as a parameter and analyze it
def analyzePacket(packet):

    global allProbes
    global countsOfProbes
    global totalCapturedProbes

    try:
        #For the packet, get the if it is a request probe layer and decode it
        if packet.haslayer(Dot11ProbeReq):
            SSID = packet.getlayer(Dot11Elt).info.decode('utf-8')
            MAC = packet.getlayer(Dot11FCS).addr2
            #If its a probe requests that has a payload (SSID) add it to the allProbes list
            if SSID != '':


                #Update total probe count
                totalCapturedProbes = totalCapturedProbes + 1

                #Add probe mac and SSID to list
                allProbes.append([MAC, SSID])

                #Make Dictionay Key out of MAC and SSID
                key = str(MAC) + str(SSID)

                #See if key is in dictionary, if it is plus one otherwise make the key and set it to one
                try:
                    if key in countsOfProbes.keys():
                        countsOfProbes[key] = countsOfProbes[key] + 1
                    if key not in countsOfProbes.keys():
                        countsOfProbes[key] = 1
                except Exception as e:
                    print ('Error here: ' + str(e))
                    pass
                
                #This code allows for update of total dynamically in terminal
                sys.stdout.flush()
                sys.stdout.write('\rTotal captured probe requests: {}'.format(totalCapturedProbes))

                
    except Exception:
        #Pass as the SSID field has no info parameter and therefore is irrelevant
        pass



#The following monitors all traffic on the interface in monitor mode using Pyshark
def monitorTraffic():

    print('[+] Starting to monitor traffic. . . hit CTRL+C to stop')



    #This will sniff traffic until a keyboard interrupt is given and analyze all packets via analyzePacket()
    sniff(iface=specifiedInterface, prn=analyzePacket)

    #Take interface out of monitor mode
    print('\n[+] Taking interface out of monitor mode')
    time.sleep(5)
    subprocess.Popen(["airmon-ng","stop", specifiedInterface],stdout=subprocess.PIPE)

#Algorithm to filter out legitmate probe requests and perform analytics
def runAlgo():

    deviceTotals = {}

    #To start we will print the total count of SSID and client macs
    print('\n[+] Analyzing ' + str(totalCapturedProbes) + ' probe requests. . . please wait. . .\n')

    print('All Captured Probe Requests ')
    print('# of Probes\t\tMAC Address\t\t\t\tSSID')
    for key in countsOfProbes.keys():
        MAC = str(key)[0:17]
        SSID = str(key)[17:]
        print(str(countsOfProbes[key]) + '\t\t\t' + MAC + '\t\t\t' + SSID)
    
    #Next we will remove SSIDs that are legitiate, leaving only bogus SSIDs
    print ('\nAll Captured Probe Requests Minus Legitimate Access Points')
    print('# of Probes\t\tMAC Address\t\t\t\tSSID')
    for key in countsOfProbes.keys():
        MAC = str(key)[0:17]
        SSID = str(key)[17:]

        #Add in total device probe count
        if MAC in deviceTotals.keys():
            deviceTotals[MAC] = deviceTotals[MAC] + countsOfProbes[key]
        if MAC not in deviceTotals.keys():
            deviceTotals[MAC] = countsOfProbes[key]

        #List of AP's detected earlier
        if SSID not in detectedAPS:
            print(str(countsOfProbes[key]) + '\t\t\t' + MAC + '\t\t\t' + SSID)

    #We will now output how to interpret this data

    #The following shows the device with the most outgoing probe requests
    max_key = max(deviceTotals, key=lambda k: deviceTotals[k])
    print ('\n[+] Results')
    print ('\t - The Device with most bogus probe requests is ' + str(max_key) + ' with ' + str(deviceTotals[max_key]) + ' requests')
    print ('\t\t A closer look should be taken at the SSID field to see if data is being exfiltrated')


if __name__ == "__main__":

    os.system('clear')
    print (splashArt)
    print ("\n[+] Starting 802.11 Probe Request Exfiltration Detector. . .")
    time.sleep(2)

    #Make sure the script is run as root
    if not os.geteuid()==0:
        print ('[-] Please run the script as root\n')
        exit(1)

    #Make sure Wireless interface is disconnected from network

    if 'y' in input('[+] Is your desired wireless interface connected to a network? y or n: '):
        print('[-] Please disconnect the desired wireless interface from the network and rerun')
        exit(1)


    specifyInterface()
    monitorTraffic()
    runAlgo()

    print ('[+] Finished. Now exiting. . .')
    exit(0)
