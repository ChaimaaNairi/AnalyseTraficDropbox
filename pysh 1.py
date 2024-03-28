import pyshark
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.size'] = 12
plt.rcParams['figure.autolayout'] = True
plt.rcParams['figure.dpi'] = 250
plt.rcParams['figure.figsize'] = 5, 4

mean_ipv4 = []
mean_ipv6 = []

for capture in ['Capture_importation_dropbox.pcapng', 'Capture_Téléchargement_dropbox.pcapng', 'Capture_partage_dropbox.pcapng']:

    cap = pyshark.FileCapture(capture)
    ipv4 = 0.0
    ipv6 = 0.0
    total = 0.0

    for packet in cap:
        if 'DNS' in packet:
            # Count DNS queries by type
            if packet.dns.qry_type == '1':  # IPv4
                ipv4 += 1.0
            elif packet.dns.qry_type == '28':  # IPv6
                ipv6 += 1.0
            total += 1.0

    mean_ipv4.append(ipv4 / total)
    mean_ipv6.append(ipv6 / total)

mean_ipv4_avg = sum(mean_ipv4) / len(mean_ipv4)
mean_ipv6_avg = sum(mean_ipv6) / len(mean_ipv6)
std_ipv4 = np.std(mean_ipv4)
std_ipv6 = np.std(mean_ipv6)

plt.pie([mean_ipv4_avg, mean_ipv6_avg], labels=['IPv4', 'IPv6'], colors=['red', 'blue'], autopct='%1.1f%%')

plt.text(0.7, -1.3, f'Standard Deviation IPv4: {std_ipv4:.3f}\nStandard Deviation IPv6: {std_ipv6:.3f}', fontsize=10)

plt.show()
