Getting Started
########################################################################
Run the pythonReq.py to get the dependancies installed or run the following commands.

python3 -m pip install cryptography
python3 -m pip install --pre scapy[basic]
python3 -m pip install inotify
python3 -m pip install setproctitle

#Both Machines
Cryptography for the Fernet encryption used for sending from Attacker to Victim machine
Scapy is the library used to craft and read packets for this application to work

#Victim Machine
inotify is attach a watcher to a file or directory to detect changes which this application will then exfiltrate
setproctile is used to mask the process name of the application on the victim machine


makekey.py
########################################################################
A utility to generate a new Fernet encryption key to use with the program to read the commands
Simply run as:
python3 makekey.py

and it will make a new key called newkey.key

config.txt
########################################################################
This is the configuration file for how this application will run.

FernetKey: is the key to use made from makekey.py.
CasearShift: is the amount of characters to move when using Casear cipher encryption.

victimIp: is the victim machine's IP.

commandPort: is the port used to send commands to the victim and, command output to the attacker.

fileNamePort: is the port used to recieve the file name for the exfil command
fileDataPort: is the port used to receive the file data for the exfil command
sniffEndPort: is the port used to stop and start the name and listening ports for the exfil command

watchFileNamePort: is the port used to recieve the file name for the watch command
watchFileDataPort: is the port used to receive the file data for the watch command
watchSniffEndPort: is the port used to stop and start the name and listening ports for the watch command

How port knocks
########################################################################
The way the port knocking works is that a specific sequence of packets is required in order to get access
to receiving a file.
In this case for example by the default configuration for the exfil command the following sequence of
any amount of port 999 then one port 1005, any amount of port 1000 then one port 1005 to complete one
cycle of port knocking to save a file

999 -> 1005 -> 1000 -> 1005

In order to send a file, the file name must be sent on port 999, then confirmed by sending one port 1005
Finally the data is sent on port 1000 and finalized by sending last one port 1005


Watcher
########################################################################
dstIP is the ip address that the automatically exfiltrated files gained from inotify will be sent to.


How to use
########################################################################
Both the key.key file listed in the config.txt and the config.txt must be on both machines
And dependancies need to be installed.

In general here is the list that each one needs based on default configuration

finalAttacker.py
-key1.key
-config.txt
-casear.py
-pythonReq.py (if libraries need to be installed)

finalVictim.py
-key1.key
-config.txt
-casear.py
-logger.py
-pythonReq.py (if libraries need to be installed)



