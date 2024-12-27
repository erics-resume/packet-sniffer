import sys
from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import TCP, IP
#from scapy.sendrecv import sniff
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


# handle/manage packets coming into the network
def handle_packet(packet, log):
    # Check if packet contains TCP layer
    if packet.haslayer(TCP):
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Extract source and destination ports
        src_port = packet[TCP].sport
        dst_port =  packet[TCP].dport
        # Write packet information to log file
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


# perform packet sniffing
def main(interface, verbose=False):
    # Create log file name based on interface
    logfile_name = f"sniffer_{interface}_log.txt"
    # Open log file for writing
    with open(logfile_name, 'w') as logfile:
        try:
            # packet sniff on specified interface w/ verbose output
            if verbose:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
            else:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

    #Start packet sniffing on specified interface

# Check if script is being run directly
if __name__ == '__main__':
    # Check if correct number of arguments are provided
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit((1))
    # Is verbose mode enabled
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    # Call main function with specified interface and verbose option
    main(sys.argv[1], verbose)


