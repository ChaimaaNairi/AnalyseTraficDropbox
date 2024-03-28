import pyshark

pcap_file_path = '4gUpload.pcapng'

stun_count = 0
turn_count = 0
ice_count = 0

capture = pyshark.FileCapture(pcap_file_path)

for packet in capture:
    if 'STUN' in packet:
        stun_count += 1
    elif 'TURN' in packet:
        turn_count += 1
    elif 'ICE' in packet:
        ice_count += 1

capture.close()

# Check if any NAT traversal techniques were used
if stun_count > 0 or turn_count > 0 or ice_count > 0:
    print("L'application utilise des techniques pour traverser les NAT de type 3 (IPv4).")
    print("Techniques détectées :")
    if stun_count > 0:
        print(f"-  (STUN) : {stun_count} paquets")
    if turn_count > 0:
        print(f"-  (TURN) : {turn_count} paquets")
    if ice_count > 0:
        print(f"-  (ICE) : {ice_count} paquets")
else:
    print("Aucune technique de traversée de NAT")
