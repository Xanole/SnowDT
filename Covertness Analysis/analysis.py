import os
import sys
import time
import dpkt
import socket
import numpy as np
import math
from collections import Counter

UPSTREAM = 1
BOTH = 0
DOWNSTREAM = -1

def LocalIP(ip):
    if ip[0:3] == "10." or ip[0:4] == "172." or ip[0:4] == "192.":
        return True
    else:
        return False


def packet_size(pcap_path, direction):
    """
    print TCP payload length in directions of up (U), down (D) and both (b), respectively.
    :param str pcap_path: the pcap file's path
    :param str directon: the direction label
    :return list packet size statistic
    :return list entropy sequence
    """
    packet_count = 0
    PACKET_SUM = 40

    size_sequence = []

    f = open(pcap_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        time = ts

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        if hasattr(ip, 'src') and hasattr(ip, 'dst'):
            try:
                sip = socket.inet_ntop(socket.AF_INET, ip.src)
                dip = socket.inet_ntop(socket.AF_INET, ip.dst)
            except Exception as e:
                sip = socket.inet_ntop(socket.AF_INET6, ip.src)
                dip = socket.inet_ntop(socket.AF_INET6, ip.dst)

        p_direction = UPSTREAM if (LocalIP(sip)) else DOWNSTREAM
        length = len(tcp.data)

        if p_direction == UPSTREAM:
            size_sequence.append(length)
            # print(length)
        elif p_direction == DOWNSTREAM:
            size_sequence.append(-1 * length)
            # print(-1 * length)

        packet_count += 1
        if packet_count >= PACKET_SUM:
            break

    return size_sequence


def packet_time(pcap_path, direction):
    """
    print TCP payload length in directions of up (U), down (D) and both (b), respectively.
    :param str pcap_path: the pcap file's path
    :param str directon: the direction label
    :return list packet captured time sequence
    """
    packet_count = 0
    PACKET_SUM = 40
    start_time = 0.0

    time_sequence = []

    f = open(pcap_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        time = ts

        if start_time == 0:
            start_time = time

        time_sequence.append(time - start_time)

        packet_count += 1
        if packet_count >= PACKET_SUM:
            break

    return time_sequence


def network_speed(pcap_path, direction):
    """
    calculating network speed fluctuation at every packet
    :param str pcap_path: the pcap file's path
    :param str directon: the direction label
    :return list speed sequence
    """
    packet_count = 0
    PACKET_SUM = 40
    start_time = 0.0
    total_size = 0
    speed_sequence = []

    f = open(pcap_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        time = ts

        if start_time == 0:
            start_time = time

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        if hasattr(ip, 'src') and hasattr(ip, 'dst'):
            try:
                sip = socket.inet_ntop(socket.AF_INET, ip.src)
                dip = socket.inet_ntop(socket.AF_INET, ip.dst)
            except Exception as e:
                sip = socket.inet_ntop(socket.AF_INET6, ip.src)
                dip = socket.inet_ntop(socket.AF_INET6, ip.dst)

        p_direction = UPSTREAM if (LocalIP(sip)) else DOWNSTREAM
        length = len(tcp.data)

        total_size += length

        # speed_sequence.append(round(total_size / 1024, 2))

        consumed_time = time - start_time
        if consumed_time == 0:
            speed_sequence.append(0.0)
        else:
            speed_sequence.append(total_size / 1024 / consumed_time)

        packet_count += 1
        if packet_count >= PACKET_SUM:
            break

    return speed_sequence


if __name__ == '__main__':

    # size- and direction-related comparison
    pcap_path_1 = '10.0a7-Snowflake.pcap'
    pcap_path_2 = 'Chrome-file.pcap'
    size_sequence_1 = packet_size(pcap_path_1, BOTH)
    size_sequence_2 = packet_size(pcap_path_2, BOTH)
    for i in range(40):
        print(i, size_sequence_1[i], size_sequence_2[i])


    pcap_path_1 = '10.0a7-Snowflake.pcap'
    pcap_path_2 = 'webpage.pcap'
    pcap_path_3 = 'video.pcap'
    pcap_path_4 = 'audio.pcap'
    pcap_path_5 = 'image.pcap'
    pcap_path_6 = 'Chrome-file.pcap'

    # time-related comparison
    time_sequence_1 = packet_time(pcap_path_1, BOTH)
    time_sequence_2 = packet_time(pcap_path_2, BOTH)
    time_sequence_3 = packet_time(pcap_path_3, BOTH)
    time_sequence_4 = packet_time(pcap_path_4, BOTH)
    time_sequence_5 = packet_time(pcap_path_5, BOTH)
    time_sequence_6 = packet_time(pcap_path_6, BOTH)
    for i in range(40):
        print(i, time_sequence_1[i], time_sequence_2[i], time_sequence_3[i], time_sequence_4[i], time_sequence_5[i], time_sequence_6[i])

    # speed-related comparsion
    speed_sequence_1 = network_speed(pcap_path_1, BOTH)
    speed_sequence_2 = network_speed(pcap_path_2, BOTH)
    speed_sequence_3 = network_speed(pcap_path_3, BOTH)
    speed_sequence_4 = network_speed(pcap_path_4, BOTH)
    speed_sequence_5 = network_speed(pcap_path_5, BOTH)
    speed_sequence_6 = network_speed(pcap_path_6, BOTH)
    for i in range(40):
        print(i, speed_sequence_1[i], speed_sequence_2[i], speed_sequence_3[i], speed_sequence_4[i], speed_sequence_5[i], speed_sequence_6[i])



