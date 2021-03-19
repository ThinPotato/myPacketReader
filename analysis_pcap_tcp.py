import dpkt
import socket

# Grab raw binary information
rawPacket = open('packet.pcap','rb')
pcap = dpkt.pcap.Reader(rawPacket)
flowCount = 0
packetsList = []
ipList = []
lastPacketBeforeCloseLocation = 0
packetSize = 0

# Convert byte data to numbers
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# Create a new flow and parse the data
def new_flow():
    global flowCount
    global packetsList
    global ipList
    for i, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            # We are only interested in IP packets
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            # We are only interested in TCP
            continue
        tcp = ip.data

        # Count flows
        if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
            flowCount +=1
             
        # load into packetsList
        packetsList.append(tcp)
        ipList.append(ip)

        # TODO: should I combine all packets from same IP and port into a group?
       
        
        
        # # For the first two transactions, print the values of the
        # # Seq number, Ack number, and Recieve window size
       

        # #TODO: Print Sender throughput aka part (3)

        #
        

new_flow()

#Check for 3 way handshakes
for x in range(len(packetsList)-3):
    #if ((packetsList[x].flags & dpkt.tcp.TH_SYN) and ((packetsList[x+1].flags & dpkt.tcp.TH_ACK) and (packetsList[x+1].flags & dpkt.tcp.TH_SYN) and packetsList[x+2].flags & dpkt.tcp.TH_ACK)):
    if (packetsList[x].flags & dpkt.tcp.TH_SYN) and (packetsList[x].flags & dpkt.tcp.TH_ACK):
        # Print Basic Data 
            # part (a)
        print("Source Port: ", packetsList[x].sport)
        print("Source IP: ", inet_to_str(ipList[x].src))
        print("Destination Port: ", packetsList[x].dport)
        print("Destination IP: ", inet_to_str(ipList[x].dst))
            # part (b)
        print("\nFirst Transaction:")
        print("    Sequence number: ", packetsList[x+2].seq )
        print("    Ack number: ", packetsList[x+2].ack)
        print("    Window size: ", packetsList[x+2].win)
        print("\nSecond Transaction:")
        print("    Sequence number: ", packetsList[x+3].seq )
        print("    Ack number: ", packetsList[x+3].ack)
        print("    Window size: ", packetsList[x+3].win)
        # Check for last sections final location
        if(x > 1):
            for y in range(lastPacketBeforeCloseLocation, x-1):
                packetSize += len(packetsList[y])
        lastPacketBeforeCloseLocation = x-1
        print("size: ",packetSize, "bytes")
        
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
# Print total number of flows
print(flowCount, "flows detected")
