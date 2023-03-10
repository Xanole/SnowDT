import os
import dpkt
import socket
import csv
import time
import math
import numpy as np
from collections import Counter


UPSTREAM = 1
BOTH = 0
DOWNSTREAM = -1

PADDING = -1


class PacketMeta(object):
    """
    the structure of a packet
    :timestamp the captured time
    :size TCP payload length
    :direction 1: c2s, -1: s2c
    """
    def __init__(self):
        super(PacketMeta, self).__init__()
        self.timestamp = None
        self.size = None
        self.direction = 0


def LocalIP(ip):
    """label local IP, especially of client"""
    if ip[0:3] == "10." or ip[0:4] == "172." or ip[0:4] == "192.":
        return True
    else:
        return False


def extract_flow(pcap_path, packet_sum):
    """
    extract every packet's information to form a flow
    :param pcap_path string: a given path of pacp file
    :param packet_sum int: the first n packets
    :return flow list: packet information list of a flow
    """
    flow = []
    packet_count = 0

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

        sport = tcp.sport
        dport = tcp.dport

        packet_count += 1
        if packet_count > packet_sum:
            break

        direction = UPSTREAM if (LocalIP(sip)) else DOWNSTREAM
        length = len(tcp.data)

        pkt = PacketMeta()
        pkt.timestamp = time
        pkt.size = length
        pkt.direction = direction

        flow.append(pkt)

    f.close()

    return flow


def time_bins(flow, direction):
    """
    percentage of intervals between packets in a given direction that falls in to a given bin
    :param flow list: a flow contain a series of packets
    :param direction int: a given direction
    :return res list: percentage of every bin
    """
    _tmp = []
    for p in flow:
        if p.direction == direction:
            _tmp.append(p.timestamp)
        else:
            continue

    data = [(y - x) * 1000 for x, y in zip(_tmp, _tmp[1:])]
    bins = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000])
    if not data:
        return [0] * 29
    digitized = np.digitize(data, bins)
    tmp = Counter(digitized)
    total = len(data)
    res = []
    for k in range(1, 30):
        if k not in tmp:
            res.append(0)
        else:
            res.append(round(float(tmp[k]) / total, 2))

    return res


def top5_size(flow, direction):
    """
    packet size distribution in a given direction
    :param flow list: a flow contain a series of packets
    :param direction int: a given direction
    :return res list: the top 5 most seen packet size
    """
    _size = []
    for p in flow:
        if p.direction == direction:
            _size.append(p.size)
        else:
            continue
    r = Counter(_size)
    res = sorted(r.items(), key=lambda x:x[1], reverse=True)[:5]
    res = [v[0] for v in res]

    if len(res) < 5:
        res += [PADDING] * (5 - len(res))

    return res


def top5_size_percentage(flow, direction):
    """
    packet size distribution in a given direction
    :param flow list: a flow contain a series of packets
    :param direction int: a given direction
    :return res list: the top 5 most seen packet size's percentage
    """
    _size = []
    for p in flow:
        if p.direction == direction:
            _size.append(p.size)
        else:
            continue
    r = Counter(_size)
    total = sum(r.values())
    res = sorted(r.items(), key=lambda x:x[1], reverse=True)[:5]
    res = [(v[0], round(float(v[1]) / total * 100, 2)) for v in res]
    res = [v[1] for v in res]

    if len(res) < 5:
        res += [PADDING] * (5 - len(res))

    return res


def direction_sum(flow, direction):
    """
    total number of packets in a given direction
    :param flow list: a flow contain a series of packets
    :param direction int: a given direction
    :return res int: total number of packets
    """
    count = 0
    for p in flow:
        if p.direction == direction:
            count += 1
    res = count

    return res


def direction_percentage(flow, direction):
    """
    percentage of packets in a given direction
    packet size distribution in a given direction
    :param flow list: a flow contain a series of packets
    :param direction int: a given direction
    :return res float: percentage of packets in a given direction
    """
    count = 0
    sum = len(flow)
    for p in flow:
        if p.direction == direction:
            count += 1
    res = round(count / sum * 100, 2)

    return res


def direction_ratio(flow, direction):
    """
    direction ratio
    :param flow list: a flow contain a series of packets
    :param direction int: a given direction
    :return res float: down/up
    """
    up_count = 0
    down_count = 0
    for p in flow:
        if p.direction == UPSTREAM:
            up_count += 1
        if p.direction == DOWNSTREAM:
            down_count += 1
    if up_count == 0:
        res = -1
    else:
        res = round(down_count / up_count * 100, 2)

    return res


def network_speed(flow):
    """
    calculating network speed at the last packet in every direction
    :param flow list: a flow contain a series of packets
    :return list: speed at up, down and both
    """
    both_total_size = 0
    up_total_size = 0
    down_total_size = 0

    both_time = 0
    up_time = 0
    down_time = 0

    for p in flow:
        both_time = p.timestamp
        both_total_size += p.size

        if p.direction == UPSTREAM:
            up_time = p.timestamp
            up_total_size += p.size
        elif p.direction == DOWNSTREAM:
            down_time = p.timestamp
            down_total_size += p.size

    if both_time == 0:
        both_speed = -1
    else:
        both_speed = both_total_size / both_time

    if up_time == 0:
        up_speed = -1
    else:
        up_speed = up_total_size / up_time

    if down_time == 0:
        down_speed = -1
    else:
        down_speed = down_total_size / down_time

    return [both_speed, up_speed, down_speed]


if __name__ == '__main__':

    FLOW_LENGTH = 30

    # pcap_archive = 'normal'
    # csv_path = 'normal_train_' + str(FLOW_LENGTH) + '.csv'

    pcap_archive = 'snowflake'
    csv_path = 'snowflake_train_' + str(FLOW_LENGTH) + '.csv'

    f = open(csv_path, 'w', newline='')

    for pcap in os.listdir(pcap_archive):
        pcap_path = os.path.join(pcap_archive, pcap)

        # print(pcap_path)
        flow = extract_flow(pcap_path, FLOW_LENGTH)
        res = []

        # F1
        for direction in [UPSTREAM, DOWNSTREAM]:
            tmp = time_bins(flow, direction)
            res += tmp
        # F2
        for direction in [UPSTREAM, DOWNSTREAM]:
            tmp = top5_size(flow, direction)
            res += tmp
        # F3
        for direction in [UPSTREAM, DOWNSTREAM]:
            tmp = top5_size_percentage(flow, direction)
            res += tmp
        # F4
        for direction in [UPSTREAM, DOWNSTREAM]:
            tmp = direction_sum(flow, direction)
            res.append(tmp)
        # F5
        for direction in [UPSTREAM, DOWNSTREAM]:
            tmp = direction_percentage(flow, direction)
            res.append(tmp)
        # F6
        tmp = direction_ratio(flow, BOTH)
        res.append(tmp)
        # F7
        # tmp = network_speed(flow)
        # res += tmp

        print(res)

        # write res not none
        if res:
            f_csv = csv.writer(f)
            f_csv.writerow(res)

    f.close()

    print('OK.')
