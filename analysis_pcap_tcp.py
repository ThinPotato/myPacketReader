import dpkt

rawPacket = open('packet.pcap')
pcap = dpkt.pcap.Reader(rawPacket)
print(pcap)