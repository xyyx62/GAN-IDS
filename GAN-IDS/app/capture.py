#!/usr/bin/env python2
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
Using Pypcap module to capture the packet and Using the Dpkt to read the packet
and save it to a .pcap file by timestamp or you can name it by yourself
by Tenkey 
"""
#from app import app

import pcap
import dpkt
import datetime
from forms import Upload, ProtoFilter
import socket
import os
import shutil
from dpkt.compat import compat_ord

import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

file_name_time = None


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_packets(pcap):
    """Print out information about each packet in a pcap
       Args:
           pcap: an pcap.pcap object (a network packet) 
    """

    # For each packet in the pcap process the contents
    global file_name_time

    with open('unnamed.pcap', 'wb') as file:
        writer = dpkt.pcap.Writer(file)
	#file_size = 0

        for timestamp, buf in pcap:

            if file_name_time == None:
                file_name_time = str(
                    datetime.datetime.utcfromtimestamp(timestamp))

            writer.writepkt(buf, timestamp)
            if os.path.getsize('unnamed.pcap') > 100000:
                break

		
		
            # Print out the timestamp in UTC
           # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

            # Unpack the Ethernet frame (mac src/dst, ethertype)
            #eth = dpkt.ethernet.Ethernet(buf)
           #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

            # Make sure the Ethernet data contains an IP packet
            #if not isinstance(eth.data, dpkt.ip.IP):
                #print('Non IP Packet type not supported %s\n' %
                      #eth.data.__class__.__name__)
                #continue

            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            #ip = eth.data

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            #do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            #more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            #fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Print out the info
            #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' %
            #      (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, #fragment_offset))

            # Print out the detials in packet
            #if isinstance(ip.data, dpkt.tcp.TCP):
                #tcp = ip.data
             #  print('TCP: SrcPort[%d] -> DstPort[%d] Seq=%d Ack=%d Win=%d\n' %
             #         (tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.win))
            #elif isinstance(ip.data, dpkt.udp.UDP):
                #udp = ip.data
             #  print('UDP: SrcPort[%d] -> DstPort[%d] Len=%d Check=%d\n' %
              #        (udp.sport, udp.dport, udp.ulen, udp.sum))
            #elif isinstance(ip.data, dpkt.icmp.ICMP):
             #   print("ICMP: This is ICMP packet for checking error on route\n")'''
            #else:
             #   print("Other Protocol: there may be other Protocols\n")'''


def getPcap():
    nic = "ens33"
    fil = None

    #ans_nc = input("do you want to set filter for network card ? [y/n]\n")
    #if ans_nc == "y":
        #nic = input("typing in the network card name:\n")
        #print("......setting filter for network card sucessfully......\n")

   # ans_fil = input(
    #    "do you want to set filter in th BPF(Berkeley Packet Filter) syntax ? [y/n]\n")
    #if ans_fil == "y":
        #fil = input("typing the BPF syntax Filter:\n")
        #print("......setting filter in BPF syntax sucessfully......\n")

    sniffer = pcap.pcap(nic)

    #if fil != None:
    #    sniffer.setfilter(fil)

    return sniffer


def main():
    """Using Pypcap(pcap) and DPKT(dpkt) modules to capture the network packet
       and unpack the packet to show the detials in every layer(this demo just show parts of them)
       and then save it into a .pcap file which can be opened by various open-source network capturing tools such as wireshark 
    """
    sniffer = getPcap()

    #print("-------------Start to Unpack-------------\n")
    
    

    #try:
    print_packets(sniffer)
    #except KeyboardInterrupt:
        #print("-------------Unpack Ended-------------\n")
        #nf = input(
        #    "Do you want to name your capture file ? (or it will automatically named by time) [y/n]\n")
        #if nf == "y":
            #file_name_user = input("Just type the name: \n")
            #os.rename('unnamed.pcap', file_name_user+'.pcap')
        #if nf == "n":
    des_pos = "/home/xiaoyue/Pcap-Analyzer-master/PCAPS/"
    os.rename('unnamed.pcap', file_name_time+'.pcap')
	
    if not os.path.exists(unicode(des_pos, 'utf-8')):
           os.mkdir(unicode(des_pos, "utf-8"))
    src_file = file_name_time+'.pcap'
    des_file = des_pos+'/'+src_file
    shutil.copyfile(src_file,des_file)
    print(src_file)

    return src_file
            #print("File will automatically be named after time , Bye~\n")
        #print("-------------Saving sucessfully-------------\n")


if __name__ == '__main__':
    main()
