#!/usr/bin/python

import socket
import os
import struct
import binascii

sock_created = False
sniffer_socket = 0

def analyze_udp_header(recv_data):
    udp_hdr = struct.unpack("!4H", recv_data[:8])
    src_port = udp_hdr[0]
    dst_port = udp_hdr[1]
    length = udp_hdr[2]
    checksum = udp_hdr[3]
    recv_data = recv_data[8:]
    
    print "|============UDP HEADER===============|"
    print "|\tSource:\t\t%hu" % src_port
    print "|\tDest:\t\t%hu" % dst_port
    print "|\tLength:\t\t%hu" % length
    print "|\tChecksum:\t%hu" % checksum
    return recv_data

def analyze_tcp_header(recv_data):
    tcp_hdr = struct.unpack("!2H2I4H", recv_data[:20])
    src_port = tcp_hdr[0]
    dst_port = tcp_hdr[1]
    seq_num  = tcp_hdr[2]
    ack_num  = tcp_hdr[3]
    data_off = tcp_hdr[4] >> 12
    reserved = tcp_hdr[4] >> 6  # Must be zero
    flags    = tcp_hdr[4] & 0x003f
    window   = tcp_hdr[5]
    checksum = tcp_hdr[6]
    urg_ptr  = tcp_hdr[7]
    data = recv_data[20:]

    urg = bool(flags & 0x0020)
    ack = bool(flags & 0x0010)
    psh = bool(flags & 0x0008)
    rst = bool(flags & 0x0004)
    syn = bool(flags & 0x0002)
    fin = bool(flags & 0x0001)

    print "|============TCP HEADER===============|"
    print "|\tSource:\t%hu" % src_port
    print "|\tDest:\t\t%hu" % dst_port
    print "|\tSeq:\t\t%hu" % seq_num
    print "|\tAck:\t%hu" % ack_num
    print "|\tFlags:"
    print "|\t\tURG:%d" % urg
    print "|\t\tACK:%d" % ack
    print "|\t\tPSH:%d" % psh
    print "|\t\tRST:%d" % rst
    print "|\t\tSYN:%d" % syn
    print "|\t\tFIN:%d" % fin
    print "|\tWindow:\t\t%hu" % window
    print "|\tChecksum:\t%s|" % checksum


    return recv_data


def analyze_ip_header(recv_data):
    ip_hdr = struct.unpack("!6H4s4s", recv_data[:20])
    ver = ip_hdr[0] >> 12 # Shift 12 bits
    ihl = (ip_hdr[0] >> 8) & 0x0f # 00001111 & 01010101 = 00000101
    tos = ip_hdr[0] & 0x00ff # 0000000011111111
    tot_len = ip_hdr[1]
    ip_id = ip_hdr[2]
    flags = ip_hdr[3] >> 13 # only the first 3 bits
    frag_offset = ip_hdr[3] & 0x1FFF #1110
    ip_ttl = ip_hdr[4] >> 8
    ip_proto = ip_hdr[4] & 0x00ff
    chk_sum = ip_hdr[5]
    src_addr = socket.inet_ntoa(ip_hdr[6])
    dst_addr = socket.inet_ntoa(ip_hdr[7])

    no_frag = flags >> 1
    more_frag = flags & 0x1

    print "|============IP HEADER===============|"
    print "|\tVersion:\t%hu" % ver
    print "|\tIHL:\t\t%hu" % ihl
    print "|\tToS:\t\t%hu" % tos
    print "|\tTotal Length:\t%hu" % tot_len
    print "|\tID:\t\t%hu" % ip_id
    print "|\tNo Frag:\t%hu" % no_frag
    print "|\tMore Frag:\t%hu" % more_frag
    print "|\tOffset:\t\t%hu" % frag_offset
    print "|\tTTL:\t\t%hu" % ip_ttl
    print "|\tNext Proto:\t%hu" % ip_proto
    print "|\tChecksum:\t%hu" % chk_sum
    print "|\tSource IP:\t%s" % src_addr
    print "|\tDest IP:\t%s" % dst_addr

    if ip_proto == 6: # TCP magic number
        next_proto = "TCP"
    elif ip_proto == 17: # UDP magic number
        next_proto = "UDP"
    else:
	next_proto == "OTHER"


    recv_data = recv_data[20:]
    return recv_data, next_proto

def analyze_ether_header(recv_data):
    ip_bool = False
    eth_hdr = struct.unpack("!6s6sH", recv_data[:14])
    dest_mac = binascii.hexlify(eth_hdr[0]) # destination address
    src_mac = binascii.hexlify(eth_hdr[1]) # source address
    proto = eth_hdr[2] >> 8 # Next protocol
    recv_data = recv_data[14:]

    print "|=================ETH Header================|"
    print "|Destination MAC:\t%s:%s:%s:%s:%s:%s" % (dest_mac[0:2], dest_mac[2:4], dest_mac[4:6], dest_mac[6:8], dest_mac[8:10], dest_mac[10:12])
    print "|Source MAC:\t\t%s:%s:%s:%s:%s:%s" % (src_mac[0:2], src_mac[2:4], src_mac[4:6], src_mac[6:8], src_mac[8:10], src_mac[10:12])
    print "|Proto:\t\t%hu" % proto

    if proto == 0x08: #IPv4
        return recv_data, True
    return recv_data, False


def main():
    global sock_created
    global sniffer_socket

    if sock_created == False:
	sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	sock_created = True
	
    recv_data = sniffer_socket.recv(2048)
    
    #os.system("clear")

    recv_data, ip_bool = analyze_ether_header(recv_data)

    if ip_bool:
        recv_data, next_proto = analyze_ip_header(recv_data)
    else:
        return

    if next_proto == "TCP":
        recv_data = analyze_tcp_header(recv_data)
    elif next_proto == "UDP":
        recv_data = analyze_udp_header(recv_data)
    else:
        return

print "<--- Daniel's Packet Sniffer --->"
while True:
    main()
