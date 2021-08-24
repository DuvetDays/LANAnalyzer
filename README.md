## LAN Analyzer
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
8. `sudo apt-get install nmap`

Download OUI MAC list from the following link:  
[Download MAC list](https://macaddress.io/database-download/csv)
then rename the csv file as `mac_address.csv` and move to the same directory as this program.  
This file will be converted to database in run-time.

### Usage
`sudo python arp_spoofing.py`
(p.s. It must be in root privilege)  
![gif](https://github.com/DuvetDays/ARPSpoofing/blob/master/arp%20spoofing_1.gif?raw=true)  
`Ctrl + C` to stop the program  

### Demonstration
[Demonstration video on Youtube](https://www.youtube.com/watch?v=3Xy-h2KZG-c)

### Step by step explanation
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
[Enter] Please input the IP range you want to scan in CIDR format(e.g., 192.168.0.0/24):
```
[step3] Select **gateway** and **victim** in host list
```
[Info.] Host list:
  No.  |       IP        |         MAC         |                 Company                  | Country
[  1  ]:   192.168.0.1   -  84:0B:7C:xx:xx:xx  -             Hitron Tech Inc              -    TW
[  2  ]:  192.168.0.20   -  44:CB:8B:xx:xx:xx  -                LG innotek                -    KR
[  3  ]:  192.168.0.32   -  C8:69:CD:xx:xx:xx  -                Apple, Inc                -    US
[  4  ]:  192.168.0.43   -  34:13:E8:xx:xx:xx  -                Intel Corp                -    US
[  5  ]:  192.168.0.46   -  CC:F4:11:xx:xx:xx  -               Google, Inc                -    US
[  6  ]:  192.168.0.60   -  D4:C8:B0:xx:xx:xx  -   Prime Electronics & Satellitics Inc    -    US
[  7  ]:  192.168.0.106  -  4C:56:9D:xx:xx:xx  -                Apple, Inc                -    US

[Info.] Scan completed.
[Info.] Scan duration: 0:00:02.849517 sec.
[Info.] Number of device(s) in the subnet 192.168.0.0/24: 7
```
[step4] Select **function**  
```
[Enter] Which function do you want?
[1] Analyze other devices
[2] Attack other devices
[3] Terminate the program
```
[step5] Select **device** and **nmap option**  
```
[Enter] Which device do you want to scan?
>>
[Enter] Which nmap options do you want?
[1] -A: scan for services and OS information
[2] -O: scan for OS information
[3] No option
```
result of nmap
```
[Info.] target port scanning:

Starting Nmap 6.40 ( http://nmap.org ) at 2021-08-24 12:50 CST
Nmap scan report for 192.168.0.32
Host is up (0.0015s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
554/tcp  open  rtsp
8080/tcp open  http-proxy
MAC Address: 00:02:D1:XX:XX:XX

```
[step6] Select **attacking mode**  
```
[Info.] Please select an attacking mode:
[1] Man in the middle(MITM)
[2] Black Hole
[3] DDoS
[Enter] Function:
```
[step7] Select **sniffing mode** (if in MITM mode)  
```
[Info.] Please select the sniffing mode you want:
[1] All packets in the specific network interface
[2] Only packets related to the victim
[Enter] Sniffing mode:
```
[step8] Start to attack victim and record packets into .pacp file in the same directory
(p.s. you can use **wireshark** to open and trace .pcap file)
```
BlackHole_traffic_log.pcap  MITM_traffic_log.pcap
```
[step9] `Ctrl + C` to stop running program and restore the LAN automatically
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
