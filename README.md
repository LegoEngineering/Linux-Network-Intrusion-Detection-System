# Linux-Network-Intrusion-Detection-System
Network Intrusion Detection System
ECE 580F - Computer Network Security - Project III
By Andrew Brick
_________________________________________________________________________________________________________________________________________________________________

Setup:

This NIDS is built using the four virtual machines that compose the network described in the the project guide:

1.Monitor [Central traffic junction used to scan traffic on Linux OS connected to the internet through NAT]
2.Attacker [Kali Linux attacking VM connected through VMnet2]
3.Metasploitable Victim [Intentionally vulnerable Linux OS connected through VMnet4]
4.Windows XP Victim [Intentionally vulnerable Windows OS connected through VMnet3]

The VMs are run on VMWare Workstation 12 Pro where the network adapters are specified.
The victim and attacker VMs are all connected exclusively through the Monitor VM, which is runninng Open Vswitch to simulate the functionality of a smart switch. 
The monitor also serves as the network gateway to the internet.
Before building the system each VM was confirmed to be able to ping all other VMs in the network as well as the internet. 
No two VMs can connect without the Monitor VM running.
_________________________________________________________________________________________________________________________________________________________________

Scanning Simulation Methodology:

After booting up the machines, the network connections must be refreshed on each victim and attacking VM with the following command: /etc/init.d/networking restart 
Begin collecting log data with the following command: tcpdump –i any –Q in > filename.log
The naming convention used for testing log files was as follows: [scan types in order of scanning]_[VM scanned]_[number of scans].log
All of the scans were performed from the attacking VM using nmap. The system was designed for the following scans: 
1.nmap –sS
2.nmap –F
3.nmap –sV
4.nmap -O
5.nmap -sn
Test logs were developed using different combinations of scans on the network as well as individual victim IPs.
Logs were created by performing mutliple scans of each type on the network as well as each victim IP during benign browsing traffic. 
_________________________________________________________________________________________________________________________________________________________________

Determining Scan Characteristics:

After studying the log files the following were discovered to be characteristics of scans:
1. Scans typically include one or more of the following keywords: "Broadcast", "who-has", "Request", "reply" and "length 46".
2. Scans oftentimes send requests to a large variety of ports in a short period of time.
3. Scans send a large number of requests, which all come from the same source address.
_________________________________________________________________________________________________________________________________________________________________

Detecting Scans in Log Files:

First files ending in ".log" are scanned into the program and added to a list with the python walk function that iterates through the current working directory. 
Print the name of each file in the list and create a new list consisting of the split lines from the file.
Use the broadcast_search function to iterate through each line in each file and print the source and destination IPs followed by the time.
The broadcast_search function works as follows:
Isolate the time components from each line and conert them to usable numbers. Multiply these numbers by the appropriate values to get a seconds value that corresponds with each line.
If the string "Broadcast" is not in a given line indicate that the most recent string was not a Broadcast string by setting broadcast_count to zero.
If the line does contain "broadcast" increment the broadcast_counter and record the line's source and destination IPs with and without the port data. Convert these values into usable strings.
Only print the scan information if the most recent line was not a "broadcast_line" and if it's been at least 4.5 seconds since the last expected scan. Set the most recent scan time to reflect the current scan.
Record the unique IP in a list.
