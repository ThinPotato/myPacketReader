import dpkt
import socket
from collections import defaultdict

# Grab raw binary information
rawPacket = open('packet.pcap','rb')
flowDictionary = defaultdict(list)
pcap = dpkt.pcap.Reader(rawPacket)
flowCount = 0
estimatedWindow =1
RECIEVER = "128.208.2.198"

# Convert byte data to numbers
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# Organize flows into a dictionary, sort out useless data
def new_flow():
    global flowCount
    for i, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        # Count flows
        if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
            flowCount +=1

        flowDictionary[tcp.sport, inet_to_str(ip.src), tcp.dport, inet_to_str(ip.dst)].append(ip)

new_flow()

# Parse for data
for flows in flowDictionary:
    numofFails=0
    numofTimeout = 0
    packetsList = flowDictionary[flows]
    packetSize=0
    window =0
    for x in range(len(packetsList)):
        # Homework asks for congestion window estimated at SENDER. So we ignore port 80 which is the reciever
        if(inet_to_str(packetsList[x].src) != RECIEVER):
        # ~~~Estimate window size~~~
            # If packet is ack increase estimated window by 1
            if(packetsList[x].data.flags & dpkt.tcp.TH_ACK):
                estimatedWindow +=1

    #~~Find number of times retransmission occured~~~
        # Due to tripple ack
        subPacketsList = packetsList[x:x+6]
        if(x % 2 ==0):
            if all(v.data.ack == subPacketsList[0].data.ack for v in subPacketsList):
                if all(u.data.seq == subPacketsList[0].data.seq for u in subPacketsList):
                    numofFails += 1
                # ~~~Estimate window size~~~
                    if(inet_to_str(packetsList[x].src) != RECIEVER):
                        estimatedWindow //=2
        # Due to timeout
        if(packetsList[x-1].data.seq > packetsList[x].data.seq):
            numofTimeout += 1
        # ~~~Estimate window size~~~
            if(inet_to_str(packetsList[x].src) != RECIEVER):
                estimatedWindow //=2
        lastSeq = packetsList[x].data.seq
            # Print Basic Data, part A
                # part (a)
        if (x ==1):
            if(inet_to_str(packetsList[x].src) != RECIEVER):
                print("\n~~~NEW FLOW~~~\n")
            else:
                print("\n~~~FLOW RESPONSE FROM RECIEVER~~~\n")
            print("Source Port: ", packetsList[x+1].data.sport)
            print("Source IP: ", inet_to_str(packetsList[x+1].src))
            print("Destination Port: ", packetsList[x+1].data.dport)
            print("Destination IP: ", inet_to_str(packetsList[x+1].dst))
                # part (b)
            if(inet_to_str(packetsList[x].src) != RECIEVER):
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
    #~~~ Part A (c) ~~~
    if(inet_to_str(packetsList[x].src) != RECIEVER):
        print("throughput: ",packetSize, "bytes")
    #~~~Part B(1)~~~
    print("Calculated Average window size: ", (window * 16385)/len(packetsList))
    #~~~ Part B (2)~~~
    print("\nNumber of retramissions due to triple ACK duplicate:", numofFails)
    print("Number of retramissions due to timeout:", numofTimeout)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
# Print total number of flows Part A
print(flowCount, "flows detected")
