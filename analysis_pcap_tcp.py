import dpkt

rawPacket = open('packet.pcap','rb')
pcap = dpkt.pcap.Reader(rawPacket)
print(pcap)