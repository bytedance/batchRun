# -*- coding: utf-8 -*-
################################
# File Name   : network_scan.py
# Author      : liyanqing.1987
# Created On  : 2025-01-09 10:01:20
# Description : scan network with ping.
################################
import os
import re
import sys
import json
import time
import copy
import argparse
import ipaddress
import threading

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.insert(0, os.environ['BATCH_RUN_INSTALL_PATH'])
from common import common

os.environ['PYTHONUNBUFFERED'] = '1'
CWD = os.getcwd()


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--alive',
                        action='store_true',
                        default=False,
                        help='Only show systems that are alive.')
    parser.add_argument('-p', '--parallel',
                        type=int,
                        default=1000,
                        help='Specify the parallelism of the ip scanning, default is "1000".')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=False,
                        help='Enable debug mode.')
    parser.add_argument('-i', '--input_file',
                        default=str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config/network.list',
                        help='Read network setting from file, default is "config/network.list".')
    parser.add_argument('-o', '--output_file',
                        default=str(config.db_path) + '/network_scan/network_scan.json',
                        help='Save scan result into json file, default is "<db_path>/network_scan/network_scan.json".')

    args = parser.parse_args()

    # Check input_file.
    if not os.path.exists(args.input_file):
        common.bprint('"' + str(args.input_file) + '": No such input file.', level='Error')
        sys.exit(1)

    # Check output_dir.
    output_dir = os.path.dirname(args.output_file)

    if not os.path.exists(output_dir):
        common.bprint('Not find output directory "' + str(output_dir) + '".', level='Error')
        sys.exit(1)

    return args.alive, args.parallel, args.debug, args.input_file, args.output_file


class NetworkScan():
    def __init__(self, alive, parallel, debug, input_file, output_file):
        self.alive = alive
        self.parallel = parallel
        self.debug = debug
        self.input_file = input_file
        self.output_file = output_file
        self.output_dic = {}

    def debug_print(self, message):
        if self.debug:
            common.bprint(message, date_format='%Y%m%d %H:%M:%S')

    def parse_input_file(self):
        """
        Input file line format shoue be like below:
        ----------------
        zone ip/ip_range/cidr
        ----------------
        """
        self.debug_print('>>> Parsing input file "' + str(self.input_file) + '" ...')
        input_dic = {}

        with open(self.input_file, 'r') as IF:
            for line in IF.readlines():
                if re.match(r'^\s*$', line) or re.match(r'^\s*#.*#', line):
                    continue
                elif re.match(r'^\s*(\S+)\s+(\S+)\s*$', line):
                    my_match = re.match(r'^\s*(\S+)\s+(\S+)\s*$', line)
                    zone = my_match.group(1)
                    network = my_match.group(2)
                    input_dic.setdefault(zone, {})
                    input_dic[zone].setdefault(network, [])
                    self.output_dic.setdefault(zone, {})
                    self.output_dic[zone].setdefault(network, {})

                    if re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$', network):
                        # For ip format.
                        input_dic[zone][network].append(network)
                        self.output_dic[zone][network].setdefault(network, {'connectivity': False, 'packet': 0, 'received': 0, 'packet_loss': '', 'rtt_avg': 0.0, 'rtt_unit': ''})
                    elif re.match(r'^(((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3})(25[0-5]|2[0-4]\d|[01]?\d\d?)-(\d+)$', network):
                        # For ip_range format.
                        my_match = re.match(r'^(((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3})(25[0-5]|2[0-4]\d|[01]?\d\d?)-(\d+)$', network)
                        pre_ip = my_match.group(1)
                        init_num = int(my_match.group(4))
                        final_num = int(my_match.group(5))

                        if init_num >= final_num:
                            common.bprint('Invalid line on "' + str(self.input_file) + '".', level='Error')
                            common.bprint(line, color='red', display_method=1, indent=9)
                            sys.exit(1)
                        else:
                            for num in range(init_num, final_num+1):
                                ip = str(pre_ip) + str(num)
                                input_dic[zone][network].append(ip)
                                self.output_dic[zone][network].setdefault(ip, {'connectivity': False, 'packet': 0, 'received': 0, 'packet_loss': '', 'rtt_avg': 0.0, 'rtt_unit': ''})
                    elif re.match(r'^(((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3})(25[0-5]|2[0-4]\d|[01]?\d\d?)/(\d+)$', network):
                        # For cidr format.
                        ip_list = list(ipaddress.IPv4Network(network).hosts())
                        del ip_list[0]

                        for ip in ip_list:
                            ip = str(ip)
                            input_dic[zone][network].append(ip)
                            self.output_dic[zone][network].setdefault(ip, {'connectivity': False, 'packet': 0, 'received': 0, 'packet_loss': '', 'rtt_avg': 0.0, 'rtt_unit': ''})
                else:
                    common.bprint('Invalid line on "' + str(self.input_file) + '".', level='Error')
                    common.bprint(line, color='red', display_method=1, indent=9)
                    sys.exit(1)

        return input_dic

    def network_scan(self, input_dic):
        self.debug_print('>>> Scaning network ...')
        thread_list = []

        for zone in input_dic.keys():
            for network in input_dic[zone].keys():
                for ip in input_dic[zone][network]:
                    thread = threading.Thread(target=self.ping_ip, args=(zone, network, ip))
                    thread_list.append(thread)

        # Run commands in thread_list in parallel.
        alive_thread_list = []

        for thread in thread_list:
            thread.start()
            alive_thread_list.append(thread)

            while self.parallel and (len(alive_thread_list) >= self.parallel):
                time.sleep(1)
                tmp_thread_list = copy.copy(alive_thread_list)

                for alive_thread in tmp_thread_list:
                    if not alive_thread.is_alive():
                        alive_thread_list.remove(alive_thread)

        for alive_thread in alive_thread_list:
            alive_thread.join()

        # Remove "connectivity == False"
        tmp_output_dic = copy.deepcopy(self.output_dic)

        if self.alive:
            for zone in tmp_output_dic.keys():
                for network in tmp_output_dic[zone].keys():
                    for ip in tmp_output_dic[zone][network].keys():
                        if not tmp_output_dic[zone][network][ip]['connectivity']:
                            del self.output_dic[zone][network][ip]

    def ping_ip(self, zone, network, ip):
        """
        ping pass output format:
        ----------------
        [liyanqing.1987@n232-134-073 tools]$ ping -w 3 10.212.204.140
        PING 10.212.204.140 (10.212.204.140) 56(84) bytes of data.
        64 bytes from 10.212.204.140: icmp_seq=1 ttl=55 time=0.196 ms
        64 bytes from 10.212.204.140: icmp_seq=2 ttl=55 time=0.181 ms
        64 bytes from 10.212.204.140: icmp_seq=3 ttl=55 time=0.177 ms
        64 bytes from 10.212.204.140: icmp_seq=4 ttl=55 time=0.183 ms

        --- 10.212.204.140 ping statistics ---
        4 packets transmitted, 4 received, 0% packet loss, time 2999ms
        rtt min/avg/max/mdev = 0.177/0.184/0.196/0.011 ms
        ----------------

        ping fail output format:
        ----------------
        [liyanqing.1987@n232-134-073 tools]$ ping -w 3 10.249.75.243
        PING 10.249.75.243 (10.249.75.243) 56(84) bytes of data.

        --- 10.249.75.243 ping statistics ---
        4 packets transmitted, 0 received, 100% packet loss, time 2999ms
        ----------------
        """
        self.debug_print('    Scaning ' + str(zone) + '  ' + str(network) + '  ' + str(ip))

        packets_compile = re.compile(r'^\s*(\d+)\s+packets transmitted,\s+(\d+)\s+received,\s+(\d+%)\s+packet loss,.*$')
        rtt_compile = re.compile(r'^\s*rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+ (\S+)\s*')
        command = 'ping -w 3 ' + str(ip)
        (return_code, stdout, stderr) = common.run_command(command)

        for line in str(stdout, 'utf-8').split('\n'):
            if packets_compile.match(line):
                my_match = packets_compile.match(line)
                packet = int(my_match.group(1))
                received = int(my_match.group(2))
                packet_loss = my_match.group(3)
                self.output_dic[zone][network][ip]['packet'] = packet
                self.output_dic[zone][network][ip]['received'] = received
                self.output_dic[zone][network][ip]['packet_loss'] = packet_loss

                if packet and received:
                    self.output_dic[zone][network][ip]['connectivity'] = True
            elif (ip in self.output_dic[zone][network]) and rtt_compile.match(line):
                my_match = rtt_compile.match(line)
                rtt_avg = float(my_match.group(1))
                rtt_unit = my_match.group(2)
                self.output_dic[zone][network][ip]['rtt_avg'] = rtt_avg
                self.output_dic[zone][network][ip]['rtt_unit'] = rtt_unit

    def write_output_file(self):
        self.debug_print('>>> Write output file "' + str(self.output_file) + '" ...')

        with open(self.output_file, 'w') as OF:
            OF.write(str(json.dumps(self.output_dic, ensure_ascii=False, indent=4)) + '\n')

    def run(self):
        input_dic = self.parse_input_file()
        self.network_scan(input_dic)
        self.write_output_file()


################
# Main Process #
################
def main():
    (alive, parallel, debug, input_file, output_file) = read_args()
    my_network_scan = NetworkScan(alive, parallel, debug, input_file, output_file)
    my_network_scan.run()


if __name__ == '__main__':
    main()
