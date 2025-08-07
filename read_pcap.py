from scapy.all import *
from scapy.layers.all import Dot11
import sys

def get_mgmt_frames(pcap_fname):
    mgmt_frames = {}
    pkts = rdpcap(pcap_fname)
    mgmt_frame_list = [pkt for pkt in pkts if pkt.haslayer(Dot11) and pkt.type == 0]
    for i in range(len(mgmt_frame_list)):
        mgmt_frames[i] = mgmt_frame_list[i].summary()
    return mgmt_frames


def get_assoc_handshake(pcap_fname):
    handshake = {}
    pkts = rdpcap(pcap_fname)
    probe_req = [pkt for pkt in pkts if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4]
    handshake["probe_request"] = probe_req
    probe_resp = [pkt for pkt in pkts if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 5]
    handshake["probe_response"] = probe_resp
    assoc_req = [pkt for pkt in pkts if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0]
    handshake["association_request"] = assoc_req
    assoc_resp = [pkt for pkt in pkts if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1]
    handshake["association_response"] = assoc_resp
    auth = [pkt for pkt in pkts if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 11]
    handshake["authentication"] = auth
    return handshake

pcap_file = sys.argv[1]
res = get_assoc_handshake(pcap_file)
print(res)