import pyshark
from collections import Counter

pcap_file_path = '4gUpload.pcapng'

destination_ips = []

def extract_packet_info(packet):
    try:
        if 'IP' in packet:
            destination_ip = packet.ip.dst
            destination_ips.append(destination_ip)
    except AttributeError:
        pass

capture = pyshark.FileCapture(pcap_file_path)

for packet in capture:
    extract_packet_info(packet)

capture.close()

destination_ip_counts = Counter(destination_ips)

print("Nombre de fois que chaque adresse IP de destination apparaît :")
for destination_ip, count in destination_ip_counts.items():
    print(f"Adresse IP de destination : {destination_ip} | Nombre de fois : {count}")
