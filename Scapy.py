from scapy.all import sniff , TCP , UDP , IP

def analyzer(pkt):
    if pkt.haslayer(TCP):
        print("------------------------------------")
        print("TCP Package...")
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].src
        mac_src = pkt.src
        mac_dst = pkt.dst

        print("SRC-IP : " + src_ip)
        print("DST-IP: " + dst_ip)
        print("MAC_src: " + mac_src)
        print("MAC_dst: " + mac_dst)
        print("-------------------------------------")

    if pkt.haslayer(UDP):
        print("--------------------------------------")
        print("UDP Packet...")
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].src
        mac_src = pkt.src
        mac_dst = pkt.dst

        print("SRC-IP : " + src_ip)
        print("DST-IP: " + dst_ip)
        print("MAC_src: " + mac_src)
        print("MAC_dst: " + mac_dst)
        print("-------------------------------------")
            


print("------------started-------------")
sniff(iface="Wi-Fi", prn=analyzer)
