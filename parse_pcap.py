from scapy.all import *
from scapy.layers.eap import EAP, EAPOL, EAPOL_KEY, EAP_TLS, EAP_PEAP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Elt
import sys

AFC_POWER_MODES = {
    0: "LPi",
    1: "SP",
    2: "VLP",
    3: "IndoorEnabled",
    4: "IndoorAFC",
    5: "Reserved",
    6: "Reserved",
    7: "Reserved",
}

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

def get_ext_tag_data(pkts, ext_tag):
    data = {}
    for pkt in pkts:
        if pkt.haslayer(Dot11Elt):
            e = pkt[Dot11Elt]
            #addr2 will be src mac address, addr1 is dest
            pkt_id = f"{pkt.addr2}_{pkt.time}"
            while isinstance(e, Dot11Elt):
                if ext_tag == e.info[:1]:
                    data[pkt_id] = e.info
                e = e.payload
    return data

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

def afc_power_mode(fname):
    mode_by_pkt = {}
    he_op_hdr = b"$" # he operation ext tag (0x24)
    pkts = rdpcap(fname)
    beacons = get_beacon_pkts(pkts)
    raw_data = get_ext_tag_data(beacons, he_op_hdr)
    for pkt_id, data in raw_data.items():
        op_info_control_byte = data[8]
        reg_info = (op_info_control_byte >> 3) & 0b1111
        mode_by_pkt[pkt_id] = AFC_POWER_MODES.get(reg_info)
    return mode_by_pkt

def twt_support(fname, ap=False):
    val_by_pkt = {}
    he_cap_hdr = b"#" # he capabilities ext tag (0x23)
    pkts = rdpcap(fname)
    if ap == False:
        filtered_pkts = get_assoc_req(pkts)
    else:
        filtered_pkts = get_beacon_pkts(pkts)
    raw_data = get_ext_tag_data(filtered_pkts, he_cap_hdr)
    for pkt_id, data in raw_data.items():
        b = data[1]
        twt_req = (b >> 1) & 0b1
        twt_res = (b >> 2) & 0b1
        val_by_pkt[pkt_id] = {
            "TWT_Requester_Supported": bool(twt_req),
            "TWT_Responder_Supported": bool(twt_res)
        }
    return val_by_pkt

if __name__ == "__main__":
    pcap_file = sys.argv[1]
    res = get_assoc_handshake(pcap_file)
    print(res)