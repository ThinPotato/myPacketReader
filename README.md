# How to use
Either add 'packet.pcap' to the local directory OR,
change the variable pcap = dpkt.pcap.reader(/your/pcap/directory/here)

# Summary
## Algorithm in part (A)
In order to estimat the congestion window, I have an assumed starting size of 1. Every time a packet is not detected as a retransmission, that value is increased by 1. For every retransmission due to any reason, it is divided by 2, with any decimal values dropped.

## Algorithm in part (B)
### Algorithm 1
In order to determine the number of retransmissions due to a triple ACK duplicate:
Each duplicate is defined as two packets with the same SEQ number.
A triple duplicate is a set of 3 duplicates.
For every 5 packets, my program subsets the current list of packets in a flow into sets of 6 (as not to accidentally count a triple duplicate twice.) If all those packets share the same SEQ number, it increases the count by one. This count is printed at the end of the flow.

### Algorithm 2
In order to determine the number of retransmissions due to a timeout: Each packet is checked to see if its SEQ number is *smaller* than the previous. If this is the case--which it ideally should never be-- it is considered an out of order packet and will eventually need to be retransmitted. Each time this occurs, we increase the count and print it at the end of the flow.