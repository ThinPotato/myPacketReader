import dpkt
import socket

# Grab raw binary information
rawPacket = open('packet.pcap','rb')
pcap = dpkt.pcap.Reader(rawPacket)
numOfFlows = 0

# Convert byte data to numbers
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# Create a new flow and parse the data
def new_flow(eth):
    global numOfFlows
    ip = eth.data
    tcp = ip.data

    sPort = tcp.sport
    sIP = inet_to_str(ip.src)
    Dport = tcp.dport
    dIP = inet_to_str(ip.dst)

    # Count flows
    if (sPort and sIP and Dport and dIP):
        numOfFlows +=1

    # TODO: should I combine all packets from same IP and port into a group?
    # Print Basic Data 
    # part (a)
    print("Source Port: ", tcp.sport)
    print("Source IP: ", inet_to_str(ip.src))
    print("Destination Port: ", tcp.dport)
    print("Destination IP: ", inet_to_str(ip.dst))
    
    # For the first two transactions, print the values of the
    # Seq number, Ack number, and Recieve window size
    # part (b)
    print("Sequence number: ", tcp.seq )
    print("Ack number: ", tcp.ack)
    print("Window size: ", tcp.win)

    #TODO: Print Sender throughput aka part (3)

    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

# Iterate through packets in pcap
for ts, buf in pcap:
    new_flow(dpkt.ethernet.Ethernet(buf))

# Print total number of flows
print(numOfFlows, "flows")