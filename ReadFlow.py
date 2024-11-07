import dpkt
import socket

class PacketMetaData:
    def __init__(self, addr: str, type_code: int, length: int, timestamp: float):
        self.addr = addr
        self.type_code = type_code
        self.length = length
        self.timestamp = timestamp

class TypeIdentifyMP:
    TYPE_TCP_SYN 	= 1
    TYPE_TCP_FIN 	= 40
    TYPE_TCP_RST 	= 1
    TYPE_TCP_ACK 	= 1000
    TYPE_TCP 		= 1000
    TYPE_UDP 		= 3
    TYPE_ICMP 		= 10
    TYPE_IGMP 		= 9
    TYPE_UNKNOWN 	= 10

def get_meta_pkt_info(pcap_file: str, dev_id: int, parsed_pkt_num: dict, parsed_pkt_len: dict) -> list:
    meta_data_list = []

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):  # Check if packet is IPv4
                    ip = eth.data
                    addr = socket.inet_ntoa(ip.src)
                    length = len(buf)
                    ts = timestamp  # Get packet timestamp

                    parsed_pkt_num[dev_id] += 1
                    parsed_pkt_len[dev_id] += length
                    
                    type_code = TypeIdentifyMP.TYPE_UNKNOWN
                    
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        if tcp.flags & dpkt.tcp.TH_SYN:
                            type_code = TypeIdentifyMP.TYPE_TCP_SYN
                        elif tcp.flags & dpkt.tcp.TH_FIN:
                            type_code = TypeIdentifyMP.TYPE_TCP_FIN
                        elif tcp.flags & dpkt.tcp.TH_RST:
                            type_code = TypeIdentifyMP.TYPE_TCP_RST
                        else:
                            type_code = TypeIdentifyMP.TYPE_TCP
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        type_code = TypeIdentifyMP.TYPE_UDP
                    
                    meta_data_list.append(PacketMetaData(addr, type_code, length, ts))
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

    return meta_data_list

# if __name__ == '__main__':

#     parsed_pkt_num = {0: 0}
#     parsed_pkt_len = {0: 0}
#     pcap_file = './SYN DoS/SYN_DoS.pcap' 
#     dev_id = 0

#     meta_data = get_meta_pkt_info(pcap_file, dev_id, parsed_pkt_num, parsed_pkt_len)
#     # for data in meta_data:
#     #     # print(f"Address: {data.addr}, Type: {data.type_code}, Length: {data.length}, Timestamp: {data.timestamp}")
#     #     with open('./SYN DoS/SYN_DoS.txt', 'a') as f:
#     #         f.write(f"Address: {data.addr}, Type: {data.type_code}, Length: {data.length}, Timestamp: {data.timestamp}\n")

#     print(f"Total number of packets: {parsed_pkt_num[dev_id]}")
#     print(f"Total length of packets: {parsed_pkt_len[dev_id]}")

