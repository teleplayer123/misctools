from scapy.all import *
from scapy.layers.eap import EAP, EAPOL, EAPOL_KEY, EAP_TLS, EAP_PEAP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Elt
import sys

def get_dot11_pkts(pkts):
    return pkts.filter(lambda x: x.haslayer(Dot11))

def get_beacon_pkts(pkts):
    return pkts.filter(lambda x: x.haslayer(Dot11Beacon))

def get_assoc_req(pkts):
    return pkts.filter(lambda x: x.haslayer(Dot11AssoReq))

def get_assoc_resp(pkts):
    return pkts.filter(lambda x: x.haslayer(Dot11AssoResp))

def iter_dot11elt_layers(pkt):
    if pkt.haslayer(Dot11Elt):
        n = 1
        e = pkt[Dot11Elt]
        while isinstance(e, Dot11Elt):
            print(f"[+] Dot11Elt Layer {n}: {e.info}")
            n += 1
            # move to next layer
            e = e.payload
    else:
        print("[-] No Dot11Elt layers in packet")

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

def iter_dot11elt_layers(pkt):
    if pkt.haslayer(Dot11Elt):
        n = 1
        e = pkt[Dot11Elt]
        while isinstance(e, Dot11Elt):
            print(f"[+] Dot11Elt Layer {n}: {e.info}")
            n += 1
            # move to next layer
            e = e.payload
    else:
        print("[-] No Dot11Elt layers in packet")
    
def parse_eap_pkts(fname):
    eap_types = [EAP, EAPOL, EAP_TLS, EAP_PEAP, EAPOL_KEY]
    eap_pkts = []
    pkts = rdpcap(fname)
    for e in eap_types:
        pkts = pkts.filter(lambda x: x.haslayer(e))
        eap_pkts.extend(pkts)
    eap_pkts = PacketList(eap_pkts)
    eap_pkts.show()
    return eap_pkts

def search_beacon_data(fname, pat):
    pkts = rdpcap(fname)
    layer_data = {}
    beacons = get_beacon_pkts(pkts)
    for pkt in beacons:
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            pkt_id = pkt.timestamp
            while isinstance(elt, Dot11Elt):
                if pat == elt.info[:len(pat)]:
                    layer_data[pkt_id] = elt.info
                # move to next Dot11Elt layer
                elt = elt.payload
    return layer_data

if __name__ == "__main__":
    pcap_file = sys.argv[1]
    res = get_assoc_handshake(pcap_file)
    print(res)