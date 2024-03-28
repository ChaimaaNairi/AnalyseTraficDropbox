import pyshark

# Path to your packet capture file
pcap_file_path = '4gUpload.pcapng'

# Print the path of the packet capture file being read
print("Reading packet capture file:", pcap_file_path)

try:
    # Initialize a dictionary to store DNS information with timestamps
    resolved_domains = {}

    # Function to extract DNS information from packets
    def extract_dns_info(packet):
        try:
            if 'DNS' in packet:
                query_name = packet.dns.qry_name
                timestamp = packet.sniff_time
                return query_name, timestamp
        except AttributeError:
            pass
        return None, None

    # Read packet capture file
    print("Opening packet capture file...")
    capture = pyshark.FileCapture(pcap_file_path)

    # Loop through each packet
    print("Starting packet analysis...")
    for i, packet in enumerate(capture):
        print(f"Processing packet {i}...")
        # Extract DNS information
        query_name, timestamp = extract_dns_info(packet)
        if query_name:
            resolved_domains[query_name] = timestamp

except Exception as e:
    print("An error occurred:", e)

finally:
    # Close the capture file
    if 'capture' in locals():
        print("Closing packet capture file...")
        capture.close()

    # Print the number of resolved domain names and their timestamps
    print("Nombre de noms de domaines résolus :", len(resolved_domains))
    print("Domaines résolus et leurs horodatages :")
    for domain, timestamp in resolved_domains.items():
        print(f"{domain} - Résolu à : {timestamp}")