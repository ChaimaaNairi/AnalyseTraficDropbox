import pyshark

dns_with_additional_records = 0
total_dns_packets = 0

for capture in ['Capture_importation_dropbox.pcapng', 'Capture_Téléchargement_dropbox.pcapng', 'Capture_partage_dropbox.pcapng']:

    cap = pyshark.FileCapture(capture)

    for packet in cap:
        if 'DNS' in packet:
            total_dns_packets += 1
            if 'dns' in packet and 'count_add_rr' in packet.dns.field_names and int(packet.dns.count_add_rr) > 0:
                dns_with_additional_records += 1

# Check if any DNS packets contain additional records
if dns_with_additional_records > 0:
    print("Les requêtes DNS contiennent des records additionnels.")
else:
    print("Les requêtes DNS ne contiennent pas de records additionnels.")
