from scapy.all import *
import os
import struct

# ...zoznam vsetkych IP adries vysielajucich uzlov a ich pocty
ip_list = []
ip_count = []
# ...premenne pri ARP komunikacii (pocet komunikacii a IP adresy)
arp_num = 0
arp_src_ip = []
arp_targ_ip = []
arp_frames = {0: {'source_ip': '', 'target_ip': ''}}
# ...premenne pri komunikacii protokolv nad TCP/UDP (pocet a pary portov)
communication_number = 0
port_pairs = {0: {'ports': (), 'ip_pairs': ()}}
# ...premenne pri ICMP komunikacii (pocet a pary IP adries)
icmp_num = 0
icmp_frames = {0: {'ip_pairs': ()}}
# ...premenne pri TFTP komunikacii
tftp_num = 0
tftp_src_port = []
tftp_frames = {0: {'ports': (), 'ip_pairs': ()}}



# ...vynuluje globalne premenne...............................................
def nullify():
    global ip_list, ip_count, arp_src_ip, arp_targ_ip, tftp_src_port
    ip_list = arp_src_ip = arp_targ_ip = tftp_src_port = []
    ip_count = []
    global arp_num, communication_number, icmp_num, tftp_num
    arp_num = communication_number = icmp_num = tftp_num = 0
    global arp_frames, port_pairs, icmp_frames, tftp_frames
    arp_frames = {0: {'source_ip': '', 'target_ip': ''}}
    port_pairs = {0: {'ports': (), 'ip_pairs': ()}}
    icmp_frames = {0: {'ip_pairs': ()}}
    tftp_frames = {0: {'ports': (), 'ip_pairs': ()}}


# ...otvori a nacita data z pcap suboru.......................................
def get_data(new_file):
    if new_file == 'y':
        filename = input("Zadaj meno suboru: ")
    else:
        filename = new_file

    if os.path.isfile(filename):
        print("Otvara sa subor: ", filename, "\n")
        data = rdpcap(filename)
        return data, filename
    else:
        print("Subor sa neda otvorit, alebo neexistuje...\n")
        exit(True)


# ...ziska a vrati cielovu a zdrojovu MAC adresu..............................
# type - EtherType (0x800 IPv4, 0x806 ARP, 0x8dd IPv6)
def get_mac_addr(data):
    dest_mac_bytes, src_mac_bytes, type = struct.unpack('! 6s 6s H', data[:14])
    dest_mac = map('{:02x}'.format, dest_mac_bytes)
    dest_mac = ' '.join(dest_mac).upper()
    src_mac = map('{:02x}'.format, src_mac_bytes)
    src_mac = ' '.join(src_mac).upper()
    return dest_mac, src_mac, type, data[14:]


# ...ziska a vrati IP adresy..................................................
# protocol - protocol number (0x6 TCP, 0x11 UDP, 0x1 ICMP)
def get_ip_addr_ipv4(data):
    global ip_list, ip_count

    header_length = data[0]
    header_length = (header_length & 15) * 4
    protocol, src_ip, target_ip = struct.unpack('! 9x B 2x 4s 4s', data[:20])
    source_ip = '.'.join(map(str, src_ip))
    target_ip = '.'.join(map(str, target_ip))

    if source_ip not in ip_list:
        ip_list.append(source_ip)
        ip_count.append(0)

    index = ip_list.index(source_ip)
    ip_count[index] += 1

    return source_ip, target_ip, protocol, data[header_length:]


def get_ip_addr_arp(data, filtered):
    operation, src_mac, src_ip, target_ip = struct.unpack('! 6x h 6s 4s 6x 4s', data[:28])
    source_ip = '.'.join(map(str, src_ip))
    target_ip = '.'.join(map(str, target_ip))

    src_mac = map('{:02x}'.format, src_mac)
    src_mac = ' '.join(src_mac).upper()

    if filtered == "ARP":
        arp_communiation(operation, src_mac, source_ip, target_ip)
    return operation, source_ip, target_ip, data[28:]


# ...ARP komunikacia request/reply............................................
def arp_communiation(operation, src_mac, src_ip, targ_ip):
    global arp_targ_ip, arp_src_ip, arp_num
    global arp_communication_data

    if operation == 1 and targ_ip in arp_targ_ip:
        if src_ip not in arp_src_ip:
            arp_src_ip.append(src_ip)
            arp_num += 1
            arp_frames[arp_num] = {}
            arp_frames[arp_num]['source_ip'] = src_ip
            arp_frames[arp_num]['target_ip'] = targ_ip
            print_arp_communication(operation, targ_ip, None, arp_num)
        else:
            for frame in range(arp_num + 1):
                if arp_frames[frame]['source_ip'] == src_ip and arp_frames[frame]['target_ip'] == targ_ip:
                    print_arp_communication(operation, targ_ip, None, frame)

    if operation == 1 and targ_ip not in arp_targ_ip:
        arp_targ_ip.append(targ_ip)
        if src_ip not in arp_src_ip:
            arp_src_ip.append(src_ip)
        arp_num += 1
        arp_frames[arp_num] = {}
        arp_frames[arp_num]['source_ip'] = src_ip
        arp_frames[arp_num]['target_ip'] = targ_ip
        print_arp_communication(operation, targ_ip, None, arp_num)

    if operation == 2 and src_ip in arp_targ_ip and targ_ip in arp_src_ip:
        for frame in range(arp_num + 1):
            if arp_frames[frame]['source_ip'] == targ_ip and arp_frames[frame]['target_ip'] == src_ip:
                print_arp_communication(operation, src_ip, src_mac, frame)

    if operation == 2 and (src_ip not in arp_targ_ip or targ_ip not in arp_src_ip):
        arp_num += 1
        print_arp_communication(3, src_ip, src_mac, arp_num)


# ...ziska ether type.........................................................
def get_ether_type(type):
    ether_type = None
    file = open("protokoly.txt", "r")

    for line in file:
        if type in line:
            ether_type = line[8:]
            ether_type = ether_type.rstrip("\n")
            break

    file.close()
    return ether_type


# ...ziska typ ramca..........................................................
def get_frame_type(type, data):
    if type >= 1536:
        ether_type = get_ether_type(hex(type))
        type = "Ethernet II"
        return type, ether_type, None
    elif type <= 1500:
        type, protocol, ether_type = ieee_types(type, data)
        return type, ether_type, protocol


# ...ziska konkretny typ ramca, ak sa jedna o IEEE 802.3......................
# (IEEE 802.2 LLC, IEEE 802.2 SNAP, IEEE 802.3 – Novell Raw)
def ieee_types(type, data):
    ether_type = protocol = None
    payload = struct.unpack('! B B', data[:2])
    bytes = map('{:02x}'.format, payload)
    bytes = ''.join(bytes).upper()

    file = open("protokoly.txt", "r")
    for line in file:
        if hex(payload[0]) in line:
            protocol = line[5:]
            protocol = protocol.rstrip("\n")
            break
    file.seek(0)
    for line in file:
        if bytes in line:
            type = line[5:]
            type = type.rstrip("\n")
            break
        else:
            type = "IEEE 802.2 - LLC"

    file.close()
    if type == "IEEE 802.2 - LLC SNAP":
        ether_type = get_snap_ethertype(data)

    return type, protocol, ether_type


# ...ziska SNAP ethertype.....................................................
def get_snap_ethertype(data):
    ether_type = struct.unpack('! 6x H', data[:8])
    # print(hex(ether_type[0]))
    return hex(ether_type[0])


# ...ziska typ IP protokolu...................................................
def get_ip_protocol_type(protocol_num):
    protocol = None
    file = open("protokoly.txt", "r")

    for line in file:
        if protocol_num in line:
            protocol = line[8:]
            protocol = protocol.rstrip("\n")
            break

    file.close()
    return protocol


# ...ziska TCP/UDP protokol...................................................
def get_protocol(port_num):
    protocol = None
    file = open("porty.txt", "r")

    for line in file:
        if str(port_num) in line:
            protocol = line[4:]
            protocol = protocol.rstrip("\n")
            break

    file.close()
    return protocol


# ...ziska cisla prijimacieho a vysielacieho portu............................
def get_port_nums(protocol, data, filtered, src_ip, targ_ip):
    global tftp_src_port
    src_port = dest_port = None
    flag_ack = flag_rst = flag_syn = flag_fin = None

    if protocol == "TCP":
        src_port, dest_port, flag_ack, flag_rst, flag_syn, flag_fin = get_tcp_info(data)
    elif protocol == "UDP":
        src_port, dest_port = get_udp_info(data)

    dest_proto = get_protocol(dest_port)
    src_proto = get_protocol(src_port)

    if (src_proto == filtered or dest_proto == filtered) and filtered != "TFTP":
        proto_communication(src_port, dest_port, src_ip, targ_ip, flag_ack, flag_rst, flag_syn, flag_fin)
    if (dest_proto == filtered == "TFTP") or src_port in tftp_src_port or dest_port in tftp_src_port:
        tftp_communication(src_port, dest_port, src_ip, targ_ip)
        return src_port, dest_port, "TFTP"

    if src_proto:
        return src_port, dest_port, src_proto
    else:
        return src_port, dest_port, dest_proto


# ...zistuje jednotlive TFTP komunikacie......................................
def tftp_communication(src_port, dest_port, src_ip, targ_ip):
    global tftp_num, tftp_frames, tftp_src_port
    to_add = True

    if dest_port == 69:
        tftp_src_port.append(src_port)
        print("Nová komunikácia č.", tftp_num + 1)
        return

    for frame in range(tftp_num + 1):
        if src_port in tftp_frames[frame]['ports'] and dest_port in tftp_frames[frame]['ports']:
            if src_ip in tftp_frames[frame]['ip_pairs'] and targ_ip in tftp_frames[frame]['ip_pairs']:
                to_add = False

    if to_add == True:
        tftp_num += 1
        tftp_frames[tftp_num] = {}
        tftp_frames[tftp_num]['ports'] = (src_port, dest_port)
        tftp_frames[tftp_num]['ip_pairs'] = (src_ip, targ_ip)
        print("Komunikácia č.", tftp_num)
    else:
        for frame in range(tftp_num + 1):
            if src_port in tftp_frames[frame]['ports'] and dest_port in tftp_frames[frame]['ports']:
                if src_ip in tftp_frames[frame]['ip_pairs'] and targ_ip in tftp_frames[frame]['ip_pairs']:
                    print("Komunikácia č.", tftp_num)


# ...zistuje jednotlive komunikacie pre protoly nad TCP/UDP...................
def proto_communication(src_port, dest_port, src_ip, targ_ip, flag_ack, flag_rst, flag_syn, flag_fin):
    global port_pairs, communication_number
    to_add = True

    for pair in range(communication_number + 1):
        if src_ip in port_pairs[pair]['ip_pairs'] and targ_ip in port_pairs[pair]['ip_pairs']:
            if src_port in port_pairs[pair]['ports'] and dest_port in port_pairs[pair]['ports']:
                to_add = False

    if to_add == True:
        communication_number += 1
        get_flag_info(src_port, dest_port, flag_ack, flag_rst, flag_syn, flag_fin)
        print("Nová komunikácia č.", communication_number)
        port_pairs[communication_number] = {}
        port_pairs[communication_number]['ports'] = (src_port, dest_port)
        port_pairs[communication_number]['ip_pairs'] = (src_ip, targ_ip)
    else:
        for pair in range(communication_number + 1):
            if src_ip in port_pairs[pair]['ip_pairs'] and targ_ip in port_pairs[pair]['ip_pairs']:
                if src_port in port_pairs[pair]['ports'] and dest_port in port_pairs[pair]['ports']:
                    get_flag_info(src_port, dest_port, flag_ack, flag_rst, flag_syn, flag_fin)
                    print("Komunikácia č.", pair)


# ...ziska udaje z TCP flagov.................................................
def get_flag_info(src_port, dest_port, flag_ack, flag_rst, flag_syn, flag_fin):
    if flag_syn == 1 and flag_ack == flag_rst == flag_fin == 0:
        print(src_port, "->", dest_port, "[SYN]")
    if flag_syn == flag_ack == 1 and flag_fin == flag_rst == 0:
        print(src_port, "->", dest_port, "[SYN, ACK]")
    if flag_ack == 1 and flag_rst == flag_fin == flag_syn == 0:
        print(src_port, "->", dest_port, "[ACK]")
    if flag_rst == 1 and flag_fin == flag_syn == flag_ack == 0:
        print(src_port, "->", dest_port, "[RST]")
    if flag_rst == flag_ack == 1 and flag_syn == flag_fin == 0:
        print(src_port, "->", dest_port, "[RST, ACK]")
    if flag_fin == 1 and flag_ack == flag_rst == flag_syn == 0:
        print(src_port, "->", dest_port, "[FIN]")
    if flag_fin == flag_ack == 1 and flag_rst == flag_syn == 0:
        print(src_port, "->", dest_port, "[FIN, ACK]")


# ...ziska informacie o ICMP protokole........................................
def get_icmp_info(data, source_ip, target_ip, filtered):
    icmp_type = None
    type = struct.unpack('! B', data[:1])
    type = '.'.join(map(str, type))
    file = open("icmp_type.txt", "r")

    for line in file:
        if type in line:
            icmp_type = line[3:]
            icmp_type = icmp_type.rstrip("\n")
            break

    file.close()
    if filtered == "ICMP":
        icmp_communication(icmp_type, source_ip, target_ip)
    return icmp_type


# ...ICMP komunikacia.........................................................
def icmp_communication(type, source_ip, target_ip):
    global icmp_num, icmp_frames
    to_add = True

    if type == None:
        type = 'nedefinovaný typ'

    for pair in range(icmp_num + 1):
        if source_ip in icmp_frames[pair]['ip_pairs'] and target_ip in icmp_frames[pair]['ip_pairs']:
            to_add = False

    if to_add == True:
        icmp_num += 1
        print_icmp_communication(type, source_ip, target_ip, icmp_num, True)
        icmp_frames[icmp_num] = {}
        icmp_frames[icmp_num]['ip_pairs'] = (source_ip, target_ip)
    else:
        for pair in range(icmp_num + 1):
            if source_ip in icmp_frames[pair]['ip_pairs'] and target_ip in icmp_frames[pair]['ip_pairs']:
                print_icmp_communication(type, source_ip, target_ip, pair, False)


# ...ziska informacie o TCP protokole.........................................
def get_tcp_info(data):
    src_port, dest_port, seq, ack, other_data = struct.unpack('! H H L L H', data[:14])
    flag_ack = (other_data & 16) >> 4
    flag_rst = (other_data & 4) >> 2
    flag_syn = (other_data & 2) >> 1
    flag_fin = (other_data & 1)
    return src_port, dest_port, flag_ack, flag_rst, flag_syn, flag_fin


# ...ziska informacie o UDP protokole.........................................
def get_udp_info(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port


# ...vypise byty v hexadecimalnej sustave.....................................
def print_frame_data(data):
    print()

    while data:
        data_bytes = data[:16]
        to_print = map('{:02x}'.format, data_bytes)
        to_print = ' '.join(to_print).upper()
        print(to_print[:23], ' ', to_print[23:])
        data = data[16:]


# ...vypise informacie o ramci (typ, dlzka, a pod.)...........................
def print_frame_info(frame_num, frame_lenght, frame_type):
    transport_length = frame_lenght + 4
    if frame_lenght <= 60:
        transport_length = 64

    print("Rámec", frame_num)
    print("Dĺžka rámca poskytnutá pcap API:", frame_lenght, "B")
    print("Dĺžka rámca prenášaného po médiu:", transport_length, "B")
    print(frame_type)


# ...vypise IP adresy a MAC adresy............................................
def print_mac_addr(src_mac, dest_mac):
    print("Zdrojová MAC adresa: ", src_mac)
    print("Cieľová MAC adresa: ", dest_mac)


def print_ip_addr(src_ip, targ_ip):
    print("Zdrojová IP adresa: ", src_ip)
    print("Cieľová IP adresa: ", targ_ip)


# ...vypise IP adresy vysielajucich uzlov aj s maximom........................
def print_ip_list():
    global ip_list, ip_count

    print("IP adresy vysielajúcich uzlov:")

    for ip_addr in ip_list:
        print(ip_addr)

    max_val = max(ip_count)
    index = ip_count.index(max_val)
    print("\nAdresa uzla s najväčším počtom odoslaných paketov:")
    print(ip_list[index], "  ", max_val, "paketov")


# ...vypise typ protokol a ether type/ icmp type...............................
def print_protocol(protocol):
    print(protocol)


def print_type(type):
    print(type)


# ...vypise cisla portov......................................................
def print_ports(src_port, dest_port):
    print("Zdrojový port:", src_port)
    print("Cieľový port:", dest_port)


# ...vypise informacie o ICMP komunikacii.....................................
def print_icmp_communication(type, source_ip, target_ip, num, new):
    if new == True:
        print("Nová komunikácia č.", num)
        print("Odoslaný", type, "z", source_ip, "na", target_ip)
    else:
        print("Komunikácia č.", num)
        print("Odoslaný", type, "z", source_ip, "na", target_ip)


# ...vypise iformacie o ARP komunikacii.......................................
def print_arp_communication(option, ip, mac, num):
    if option == 1:
        print("Komunikácia č.", num, "(Request odoslaný)")
        print("ARP-Request, IP adresa:", ip, " MAC adresa: ???")
    if option == 2:
        print("Komunikácia č.", num, "(Reply odoslaný)")
        print("ARP-Reply, IP adresa:", ip, " MAC adresa:", mac)
    if option == 3:
        print("Komunikácia č.", num, "(Reply odoslaný)")
        print("ARP-Reply bez ARP-Request, IP adresa:", ip, " MAC adresa:", mac)


# ...zistuje, ci existuje typ, co chceme vyfiltrovat..........................
def check_existence(to_filter):
    if to_filter == '':
        return False

    file = open("protokoly.txt", "r")
    for line in file:
        if to_filter in line:
            file.close()
            return True
    file.close()

    file = open("porty.txt", "r")
    for line in file:
        if to_filter in line:
            file.close()
            return True
    file.close()

    return False


# ...zariadi aby sa vypisali len vyfiltrovane ramce...........................
def to_filter(ether_type, protocol, proto, to_filter, filtered_status):
    if filtered_status == False:
        return True
    if ether_type == to_filter:
        return True
    if protocol == to_filter:
        return True
    if proto == to_filter:
        return True


# ...main.....................................................................
def main(new_file):
    raw_data, filename = get_data(new_file)
    frame_count = 0
    filtered = input("Zadaj protokol, ktory chces vyfiltrovat: ")
    print()
    filtered_status = check_existence(filtered)

    orig_stdout = file = None
    out = input("Vypis do konzly, alebo .txt suboru: (f - subor/ ine - konzola) ")
    if out == "f":
        orig_stdout = sys.stdout
        file = open('vypis.txt', 'w')
        sys.stdout = file

    for frame in raw_data:
        source_ip = target_ip = None
        src_port = dest_port = None
        proto = icmp_type = None

        dest_mac, src_mac, type, data_frag = get_mac_addr(raw(raw_data[frame_count]))
        frame_type, ether_type, protocol = get_frame_type(type, data_frag)
        frame_lenght = len(raw_data[frame_count])

        if ether_type == "ARP":
            operation, source_ip, target_ip, data_frag = get_ip_addr_arp(data_frag, filtered)
        elif ether_type == "IPv4":
            source_ip, target_ip, protocol_num, data_frag = get_ip_addr_ipv4(data_frag)
            protocol = get_ip_protocol_type(hex(protocol_num))
            if protocol == "ICMP":
                icmp_type = get_icmp_info(data_frag, source_ip, target_ip, filtered)
            src_port, dest_port, proto = get_port_nums(protocol, data_frag, filtered, source_ip, target_ip)

        if (to_filter(ether_type, protocol, proto, filtered, filtered_status) == True):
            print_frame_info(frame_count + 1, frame_lenght, frame_type)
            print_mac_addr(src_mac, dest_mac)
            if ether_type:
                print_type(ether_type)
            if source_ip and target_ip:
                print_ip_addr(source_ip, target_ip)
            if protocol:
                print_protocol(protocol)
            if proto:
                print_protocol(proto)
            if icmp_type:
                print_type(icmp_type)
            if src_port and dest_port:
                print_ports(src_port, dest_port)
            print_frame_data(raw(raw_data[frame_count]))
            print("\n")

        frame_count += 1

    print_ip_list()
    if out == 'f':
        sys.stdout = orig_stdout
        file.close()
    print("Analyza ukoncena\n")
    return filename

filename = None
while True:
    new_file = input("Chces otvorit novy subor? (y - ano/ prazdne - nie) ")
    if new_file != 'y':
        new_file = filename
    filename = main(new_file)
    nullify()
