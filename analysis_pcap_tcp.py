import dpkt
import socket
from collections import defaultdict

# Grab raw binary information
rawPacket = open('packet.pcap','rb')
flowDictionary = defaultdict(list)
pcap = dpkt.pcap.Reader(rawPacket)
flowCount = 0
lastPacketBeforeCloseLocation = 0
packetSize = 0
numofFails = 0
estimatedWindow =1

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

        flowDictionary[tcp.sport, inet_to_str(ip.src), tcp.dport, inet_to_str(ip.dst)].append(ip)

new_flow()

#Check for 3 way handshakes
for flows in flowDictionary:
    numofFails=0
    numofTimeout = 0
    packetsList = flowDictionary[flows]
    packetSize=0
    window =0
    for x in range(len(packetsList)):
        # Homework asks for congestion window estimated at SENDER. So we ignore port 80 which is the reciever
        if(packetsList[x].data.sport != 80):
            # ~~~Estimate window size~~~
            # If packet is ack increase estimated window by 1
            if(packetsList[x].data.flags & dpkt.tcp.TH_ACK):
                estimatedWindow +=1

        #~~Find number of times retransmission occured~~
        # Due to tripple ack
        subPacketsList = packetsList[x:x+3]
        if all(v.data.ack == subPacketsList[0].data.ack for v in subPacketsList):
            if all(u.data.seq == subPacketsList[0].data.seq for u in subPacketsList):
                numofFails += 1
                if(packetsList[x].data.sport != 80):
                    estimatedWindow //=2
        # Due to timeout
        if(packetsList[x-1].data.seq > packetsList[x].data.seq):
            numofTimeout += 1
            if(packetsList[x].data.sport != 80):
                estimatedWindow //=2
        lastSeq = packetsList[x].data.seq
            # Print Basic Data 
                # part (a)
        if (x ==1):
            print("Source Port: ", packetsList[x+1].data.sport)
            print("Source IP: ", inet_to_str(packetsList[x+1].src))
            print("Destination Port: ", packetsList[x+1].data.dport)
            print("Destination IP: ", inet_to_str(packetsList[x+1].dst))
                # part (b)
            if(packetsList[x].data.sport != 80):
                print("\nFirst Transaction:")
                print("    Sequence number: ", packetsList[x+2].data.seq )
                print("    Ack number: ", packetsList[x+2].data.ack)
                print("    Window size: ", packetsList[x+2].data.win)
                print("\nSecond Transaction:")
                print("    Sequence number: ", packetsList[x+3].data.seq )
                print("    Ack number: ", packetsList[x+3].data.ack)
                print("    Window size: ", packetsList[x+3].data.win)

        if (x < 4 & x > 1):
            print("\nestimated window size for Transaction",x,":", estimatedWindow)
        packetSize += len(packetsList[x].data.data)
        
        window += dpkt.tcp.TCP_OPT_WSCALE
    if(packetsList[x].data.sport != 80):
        print("throughput: ",packetSize, "bytes")
    print("Calculated Average window size: ", (window * 16385)/len(packetsList))
        
    print("\nNumber of retramissions due to tripple ACK duplicate:", numofFails)
    print("Number of retramissions due to timeout:", numofTimeout)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
# Print total number of flows
print(flowCount, "flows detected")
