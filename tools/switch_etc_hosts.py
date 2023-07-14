# -*- coding: utf-8 -*-
################################
# File Name   : switch_etc_hosts.py
# Author      : liyanqing.1987
# Created On  : 2023-07-14 15:12:43
# Description :
################################
import os
import re
import sys
import argparse

os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input_file',
                        default='/etc/hosts',
                        help='Specify input file, default is "/etc/hosts".')
    parser.add_argument('-o', '--output_file',
                        default='./host.list',
                        help='Specify output file, default is "./host.list".')

    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print('*Error*: "' + str(args.input_file) + '": No such file.')
        sys.exit(1)

    if os.path.exists(args.output_file):
        print('*Error*: "' + str(args.output_file) + '": file exists.')
        sys.exit(1)

    return (args.input_file, args.output_file)


class SwitchEtcHosts():
    """
    Switch /etc/hosts (or similar) file into batchRun host.list file.
    """
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file

    def parse_input_file(self):
        """
        input_file must match below format.
        # GROUP : <group>
        <host_ip> <host_name>
        <host_ip> <host_name> # SSH_PORT=<port>
        """
        input_dic = {}
        group = ''

        with open(self.input_file, 'r') as IF:
            for line in IF.readlines():
                if re.match(r'^\s*$', line):
                    continue
                elif re.match(r'^\s*#\s*GROUP\s*:\s*(\S+).*$', line):
                    my_match = re.match(r'^\s*#\s*GROUP\s*:\s*(\S+).*$', line)
                    group = my_match.group(1)

                    if group in input_dic:
                        print('*Error*: group "' + str(group) + '" is defined repeatedly on "' + str(self.input_file) + '".')
                        sys.exit(1)
                    else:
                        input_dic[group] = {}
                elif re.match(r'^\s*((([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5]))\s+(\S+)\s*(#\s*SSH_PORT\s*=\s*(\d+))?\s*$', line):
                    my_match = re.match(r'^\s*((([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5]))\s+(\S+)\s*(#\s*SSH_PORT\s*=\s*(\d+))?\s*$', line)
                    host_ip = my_match.group(1)
                    host_name = my_match.group(5)
                    ssh_port = my_match.group(7)

                    if not group:
                        print('*Warning*: Not find group information for below line, igonre')
                        print('           ' + str(line))
                    else:
                        input_dic[group].setdefault(host_ip, {})
                        input_dic[group][host_ip].setdefault('host_name', [])

                        if host_name not in input_dic[group][host_ip]['host_name']:
                            input_dic[group][host_ip]['host_name'].append(host_name)
                        else:
                            print('*Error*: host_ip "' + str(host_ip) + '" & host_name "' + str(host_name) + '" is defined repeatedly on "' + str(self.input_file) + '".')
                            sys.exit(1)

                        if ssh_port:
                            input_dic[group][host_ip].setdefault('ssh_port', ssh_port)
                else:
                    print('*Warning*: Unknown/Useless content for below line, igonre')
                    print('           ' + str(line))

        return input_dic

    def write_output_file(self, input_dic):
        """
        Write output_file as batchRun host.list format.
        """
        if input_dic:
            with open(self.output_file, 'w') as OF:
                for group in input_dic.keys():
                    OF.write('\n[' + str(group) + ']\n')

                    for host_ip in input_dic[group].keys():
                        for host_name in input_dic[group][host_ip]['host_name']:
                            if 'ssh_port' in input_dic[group][host_ip]:
                                OF.write(str(host_ip) + '  ' + str(host_name) + '  ' + str(input_dic[group][host_ip]['ssh_port']) + '\n')
                            else:
                                OF.write(str(host_ip) + '  ' + str(host_name) + '\n')

            print('')
            print('Output File : ' + str(self.output_file))

    def run(self):
        input_dic = self.parse_input_file()
        self.write_output_file(input_dic)


################
# Main Process #
################
def main():
    (input_file, output_file) = read_args()
    my_switch_etc_hosts = SwitchEtcHosts(input_file, output_file)
    my_switch_etc_hosts.run()


if __name__ == '__main__':
    main()
