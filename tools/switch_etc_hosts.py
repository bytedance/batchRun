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
import copy
import argparse

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.insert(0, os.environ['BATCH_RUN_INSTALL_PATH'])
from common import common

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
                        default=str(config.host_list),
                        help='Specify output file, default is "' + str(config.host_list) + '".')
    parser.add_argument('-a', '--append',
                        default='',
                        help='Append configuration file into output file.')
    parser.add_argument('-eh', '--expected_hosts',
                        nargs='+',
                        default=[],
                        help='Specify expected ip(s), support regular expressions.')
    parser.add_argument('-eg', '--expected_groups',
                        nargs='+',
                        default=[],
                        help='Specify expected group(s), support regular expressions.')
    parser.add_argument('-EH', '--excluded_hosts',
                        nargs='+',
                        default=[],
                        help='Specify excluded ip(s), support regular expressions.')
    parser.add_argument('-EG', '--excluded_groups',
                        nargs='+',
                        default=[],
                        help='Specify excluded group(s), support regular expressions.')
    parser.add_argument('-r', '--rewrite',
                        action='store_true',
                        default=False,
                        help='Rewrite mode, rewrite output file by force.')
    parser.add_argument('-t', '--tool',
                        default='batchRun',
                        choices=['batchRun', 'ansible'],
                        help='Which tool the host list is for, default is "batchRun".')

    args = parser.parse_args()

    # input_file must exists.
    if not os.path.exists(args.input_file):
        common.bprint('"' + str(args.input_file) + '": No such input file.', level='Error')
        sys.exit(1)

    # Will exit if output_file exists without rewrite mode.
    if os.path.exists(args.output_file) and (not args.rewrite):
        common.bprint('Output file "' + str(args.output_file) + '" exists, please remote it, or enable rewrite mode.', level='Error')
        sys.exit(1)

    # Check append file exists or not.
    if args.append and (not os.path.exists(args.append)):
        args.append = ''

    return (args.input_file, args.output_file, args.append, args.expected_hosts, args.expected_groups, args.excluded_hosts, args.excluded_groups, args.tool)


class SwitchEtcHosts():
    """
    Switch /etc/hosts (or similar) file into batchRun host.list file.
    """
    def __init__(self, input_file, output_file, append_file, expected_host_list, expected_group_list, excluded_host_list, excluded_group_list, tool):
        self.input_file = input_file
        self.output_file = output_file
        self.append_file = append_file
        self.expected_host_list = expected_host_list
        self.expected_group_list = expected_group_list
        self.excluded_host_list = excluded_host_list
        self.excluded_group_list = excluded_group_list
        self.tool = tool

    def parse_input_file(self):
        """
        input_file must match below format.
        # GROUP : <group>
        <host_ip> <host_names>
        <host_ip> <host_names> # SSH_PORT=<port>
        """
        input_dic = {}
        group = ''

        with open(self.input_file, 'r') as IF:
            for line in IF.readlines():
                line = line.strip()

                if re.match(r'^\s*$', line):
                    continue
                elif re.match(r'^\s*#.*$', line):
                    if re.match(r'^\s*#\s*GROUP\s*:\s*(\S+).*$', line):
                        my_match = re.match(r'^\s*#\s*GROUP\s*:\s*(\S+).*$', line)
                        group = my_match.group(1)

                        if group in input_dic:
                            common.bprint('Group "' + str(group) + '" is defined repeatedly.', level='Error')
                            sys.exit(1)
                        else:
                            input_dic[group] = {}
                    else:
                        common.bprint('Comment line, igonre', level='Warning')
                        common.bprint(line, color=33, display_method=1, indent=11)
                elif re.match(r'^\s*((([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5]))\s+(.+?)\s*(#.*?)?\s*$', line):
                    my_match = re.match(r'^\s*((([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5]))\s+(.+?)\s*(#.*?)?\s*$', line)
                    host_ip = my_match.group(1)
                    host_names_string = my_match.group(5)
                    comment_string = my_match.group(6)
                    ssh_port = ''

                    if comment_string and re.match(r'^#\s*SSH_PORT\s*=\s*(\d+)$', comment_string):
                        my_match = re.match(r'^#\s*SSH_PORT\s*=\s*(\d+)$', comment_string)
                        ssh_port = my_match.group(1)

                    if not group:
                        common.bprint('Group missing for below line, igonre', level='Warning')
                        common.bprint(line, color=33, display_method=1, indent=11)
                    else:
                        # Save host_ip into input_dic.
                        input_dic[group].setdefault(host_ip, {})
                        input_dic[group][host_ip].setdefault('host_name', [])

                        for host_name in host_names_string.split():
                            if host_name not in input_dic[group][host_ip]['host_name']:
                                input_dic[group][host_ip]['host_name'].append(host_name)

                        if ssh_port:
                            input_dic[group][host_ip].setdefault('ssh_port', ssh_port)
                else:
                    common.bprint('Meaningless line, igonre', level='Warning')
                    common.bprint(line, color=33, display_method=1, indent=11)

        return input_dic

    def filter_input_dic(self, input_dic):
        """
        Filter input_dic with self.expected_host_list/self.expected_group_list/self.excluded_host_list/self.excluded_group_list.
        """
        filtered_input_dic = {}

        # Fill with self.expected_group_list:
        for group in input_dic.keys():
            if (not self.expected_group_list) or (group in self.expected_group_list) or self.fuzzy_match_in(group, self.expected_group_list):
                filtered_input_dic[group] = input_dic[group]

        # Filter with self.excluded_group_list:
        if self.excluded_group_list:
            group_list = list(filtered_input_dic.keys())

            for group in group_list:
                if (group in self.excluded_group_list) or self.fuzzy_match_in(group, self.excluded_group_list):
                    del filtered_input_dic[group]

        # Filter with self.expected_host_list:
        if self.expected_host_list:
            for group in filtered_input_dic.keys():
                group_dic = copy.deepcopy(filtered_input_dic[group])

                for host in group_dic.keys():
                    if (host not in self.expected_host_list) and (not self.fuzzy_match_in(host, self.expected_host_list)):
                        del filtered_input_dic[group][host]

        # Filter with self.excluded_host_list:
        if self.excluded_host_list:
            for group in filtered_input_dic.keys():
                group_dic = copy.deepcopy(filtered_input_dic[group])

                for host in group_dic.keys():
                    if (host in self.excluded_host_list) or self.fuzzy_match_in(host, self.excluded_host_list):
                        del filtered_input_dic[group][host]

        return filtered_input_dic

    def fuzzy_match_in(self, specified_item, fuzzy_item_list):
        """
        If there is a fuzzy match between specified_item and any item in fuzzy_item_list, return True; otherwise, return False.
        """
        try:
            for fuzzy_item in fuzzy_item_list:
                if re.match(fuzzy_item, specified_item):
                    return True
        except Exception as error:
            common.bprint('Failed on fuzzy matching "' + str(specified_item) + '" with "' + str(fuzzy_item_list) + '".', level='Error')
            common.bprint(error, color=31, display_method=1, indent=9)

        return False

    def write_output_file(self, input_dic):
        """
        Write output_file as batchRun host.list format.
        """
        if input_dic:
            with open(self.output_file, 'w') as OF:
                for group in input_dic.keys():
                    if input_dic[group]:
                        OF.write('\n[' + str(group) + ']\n')

                        for host_ip in input_dic[group].keys():
                            for host_name in input_dic[group][host_ip]['host_name']:
                                if self.tool == 'batchRun':
                                    if 'ssh_port' in input_dic[group][host_ip]:
                                        OF.write(str(host_ip) + '  ssh_host=' + str(host_name) + '  ssh_port=' + str(input_dic[group][host_ip]['ssh_port']) + '\n')
                                    else:
                                        OF.write(str(host_ip) + '  ssh_host=' + str(host_name) + '\n')
                                elif self.tool == 'ansible':
                                    if 'ssh_port' in input_dic[group][host_ip]:
                                        OF.write(str(host_ip) + '  ansible_ssh_host=' + str(host_name) + '  ansible_ssh_port=' + str(input_dic[group][host_ip]['ssh_port']) + '\n')
                                    else:
                                        OF.write(str(host_ip) + '  ansible_ssh_host=' + str(host_name) + '\n')

                if self.append_file:
                    with open(self.append_file, 'r') as AF:
                        for line in AF.readlines():
                            OF.write(str(line).strip() + '\n')

            common.bprint('')
            common.bprint('Output File : ' + str(self.output_file))

    def run(self):
        input_dic = self.parse_input_file()
        input_dic = self.filter_input_dic(input_dic)
        self.write_output_file(input_dic)


################
# Main Process #
################
def main():
    (input_file, output_file, append_file, expected_host_list, expected_group_list, excluded_host_list, excluded_group_list, tool) = read_args()
    my_switch_etc_hosts = SwitchEtcHosts(input_file, output_file, append_file, expected_host_list, expected_group_list, excluded_host_list, excluded_group_list, tool)
    my_switch_etc_hosts.run()


if __name__ == '__main__':
    main()
