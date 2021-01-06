## ARPSpoofing
![](https://img.shields.io/badge/platform-Linux--64-brightgreen)
![](https://img.shields.io/badge/OS-Ubuntu%2018.04%20LTS-orange)
![](https://img.shields.io/badge/python-2.7-blue)

### Description
A tool for LAN scanning, ARP attacking and packets capturing.  
For testing or teaching only.

### Prerequisite environment setup

Install python related modules by using the fellowing commands:  
1. `sudo apt install python`  
2. `sudo apt install python-pandas`
3. `sudo apt install python-pip`
4. `sudo pip install --upgrade pip enum34`
5. `sudo apt-get update -y`
6. `sudo apt-get install -y scapy`
7. `sudo apt-get install -y python-netifaces`

Download OUI mac list from the fellowing link:  
`https://macaddress.io/database-download/csv`  
then rename the csv file as `mac_address.csv` and place at the same folder.  
This file will be converted to database in run-time.

### Usage
`sudo python arp_spoofing.py`  
![gif](https://github.com/DuvetDays/ARPSpoofing/blob/master/arp%20spoofing_1.gif?raw=true)
### Demonstration
[step1] select **network interface**  
```
[Info.] Available network interface list:
[1]: lo, MAC:[{'peer': '00:00:00:00:00:00', 'addr': '00:00:00:00:00:00'}]
[2]: ens33, MAC:[{'broadcast': 'ff:ff:ff:ff:ff:ff', 'addr': '00:0c:29:xx:xx:xx'}]
```
[step2] input **IP range** of subnet you want to scan 
```
[Info.] Network config: [{'broadcast': '192.168.0.255', 'netmask': '255.255.255.0', 'addr': '192.168.0.93'}]
[Info.] MAC info: [{'broadcast': 'ff:ff:ff:ff:ff:ff', 'addr': '00:0c:29:xx:xx:xx'}]
[Enter] Please input the IP range you want to scan (e.g., 192.168.0.0/24):
```
 [step3] select **gateway** and **victim** 
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
[step4] selcet **attacking mode**  
```
[Info.] Please select an attacking mode:
[1] Man in the middle(MITM)
[2] Black Hole
[Enter] Function:
```
