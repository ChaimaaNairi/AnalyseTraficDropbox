import pyshark

dns_query_types = set()

for capture in ['Capture_importation_dropbox.pcapng', 'Capture_Téléchargement_dropbox.pcapng', 'Capture_partage_dropbox.pcapng']:

    cap = pyshark.FileCapture(capture)

    for packet in cap:
        if 'DNS' in packet:
            dns_query_types.add(packet.dns.qry_type)

# Print unique DNS query types
print("Types de requête DNS effectuées:", dns_query_types)
