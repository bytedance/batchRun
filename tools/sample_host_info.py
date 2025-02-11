# -*- coding: utf-8 -*-
################################
# File Name   : sample_host_info.py
# Author      : liyanqing.1987
# Created On  : 2024-08-12 18:34:15
# Description : Used to sample host os and hardware info.
################################
import os
import re
import sys
import json
import datetime
import argparse

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

    parser.add_argument('-H', '--hosts',
                        nargs='+',
                        default=[],
                        help='Specify host(s) for batch_run.')
    parser.add_argument('-G', '--groups',
                        nargs='+',
                        default=[],
                        help='Specify host group(s) for batch_run.')
    parser.add_argument('-u', '--user',
                        default='',
                        help='Specify the user identity for SSH login to specified host.')
    parser.add_argument('-p', '--password',
                        default='',
                        help='Specify the user password for SSH login to specified host.')
    parser.add_argument('-P', '--parallel',
                        type=int,
                        default=0,
                        help='Specify the parallelism for batch_run.')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        default=20,
                        help='Specify the timeout for batch_run.')
    parser.add_argument('-o', '--output_dir',
                        default=str(config.db_path) + '/host_info',
                        help='Specify host info output directory, default is "<db_path>/host_info".')

    args = parser.parse_args()

    # Check output_dir.
    if os.path.exists(args.output_dir):
        args.output_dir = os.path.realpath(args.output_dir)
    else:
        common.bprint('"' + str(args.output_dir) + '": No such directory.', level='Error')
        sys.exit(1)

    return args.hosts, args.groups, args.user, args.password, args.parallel, args.timeout, args.output_dir


class SampleHostInfo():
    def __init__(self, host_list, group_list, user, password, parallel, timeout, output_dir):
        self.batch_run_command = self.get_batch_run_command(host_list, group_list, user, password, parallel, timeout)
        self.output_dir = output_dir
        self.host_list_file = str(self.output_dir) + '/host_list.json'
        self.latest_host_info_file = str(self.output_dir) + '/host_info.json'
        self.old_host_info_file = os.path.realpath(self.latest_host_info_file)
        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_host_info_file = str(self.output_dir) + '/host_info.json.' + str(current_time)

    def get_batch_run_command(self, host_list=[], group_list=[], user='', password='', parallel=0, timeout=20):
        """
        Get default batch_run command (without run command).
        """
        batch_run_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run'

        if host_list:
            batch_run_command = str(batch_run_command) + ' --hosts ' + str(' '.join(host_list))

        if group_list:
            batch_run_command = str(batch_run_command) + ' --groups ' + str(' '.join(group_list))

        if user:
            batch_run_command = str(batch_run_command) + ' --user ' + str(user)

        if password:
            batch_run_command = str(batch_run_command) + ' --password ' + str(password)

        batch_run_command = str(batch_run_command) + ' --parallel ' + str(parallel)

        if timeout:
            batch_run_command = str(batch_run_command) + ' --timeout ' + str(timeout)

        return batch_run_command

    def cleanup(self):
        command = 'rm -rf *.info host_list.json'
        common.bprint('\n>>> Clean up ' + str(self.output_dir) + ' ...')
        common.bprint(command, indent=4)
        os.chdir(self.output_dir)
        os.system(command)
        os.chdir(CWD)

    def sample_host_list_info(self):
        command = str(self.batch_run_command) + ' --list --output_file ' + str(self.host_list_file)
        common.bprint('\n>>> Sampling host list information ...')
        common.bprint(command, indent=4)
        os.system(command)

    def sample_host_os_hard_info(self):
        sample_command = 'lsb_release -a; hostnamectl; lscpu; free -g'
        command = str(self.batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(self.output_dir) + '/HOST.info'
        common.bprint('\n>>> Sampling host os/cpu/mem information ...')
        common.bprint(command, indent=4)
        os.system(command)

    def collect_host_os_hard_info(self):
        common.bprint('\n>>> Collecting host information ...')
        host_list_dic = {}

        if os.path.exists(self.host_list_file):
            with open(self.host_list_file, 'r') as HLF:
                host_list_dic = json.loads(HLF.read())

        host_info_dic = self.collect_host_info(host_list_dic)
        host_info_dic = self.update_host_info(host_info_dic)

        with open(self.current_host_info_file, 'w') as HIF:
            HIF.write(str(json.dumps(host_info_dic, ensure_ascii=False, indent=4)) + '\n')

        common.bprint('Host info has been saved to file "' + str(self.current_host_info_file) + '".', indent=4)

    def collect_host_info(self, host_list_dic):
        """
        Collect host os/hardware information from sampled files under self.output_dir.
        """
        host_info_dic = {}

        # Get host_info_dic based on *.info files.
        server_type_compile = re.compile(r'^\s*Chassis:\s*(\S*)\s*$')
        os1_compile = re.compile(r'^\s*Description:\s*(.+?)\s*$')
        os2_compile = re.compile(r'^\s*Operating System:.*?([A-Z].+?\)).*$')
        cpu_architecture_compile = re.compile(r'^\s*Architecture:\s*(\S+)\s*$')
        cpu_thread_compile = re.compile(r'^\s*CPU\(s\):\s*(\d+)\s*$')
        thread_per_core_compile = re.compile(r'^\s*Thread\(s\) per core:\s*(\d+)\s*$')
        cpu_model_compile = re.compile(r'^\s*Model name:\s*(.+?)\s*$')
        cpu_frequency_compile = re.compile(r'^\s*CPU MHz:\s*([0-9\.]+)\s*$')
        mem_size_compile = re.compile(r'^\s*Mem:\s*(\d+)\s+.*$')
        swap_size_compile = re.compile(r'^\s*Swap:\s*(\d+)\s+.*$')

        for host_ip in host_list_dic.keys():
            host_info_dic.setdefault(host_ip, {'host_name': [],
                                               'groups': [],
                                               'server_type': '',
                                               'os': '',
                                               'cpu_architecture': '',
                                               'cpu_thread': 0,
                                               'thread_per_core': 0,
                                               'cpu_model': '',
                                               'cpu_frequency': 0.0,
                                               'cpu_frequency_unit': 'GHz',
                                               'mem_size': 0,
                                               'mem_size_unit': 'GB',
                                               'swap_size': 0,
                                               'swap_size_unit': 'GB'})

            if 'host_name' in host_list_dic[host_ip]:
                host_info_dic[host_ip]['host_name'] = host_list_dic[host_ip]['host_name']

            if 'groups' in host_list_dic[host_ip]:
                host_info_dic[host_ip]['groups'] = host_list_dic[host_ip]['groups']

            host_info_file = str(self.output_dir) + '/' + str(host_ip) + '.info'

            if os.path.exists(host_info_file):
                with open(host_info_file, 'r') as HIF:
                    for line in HIF.readlines():
                        if server_type_compile.match(line):
                            my_match = server_type_compile.match(line)
                            host_info_dic[host_ip]['server_type'] = my_match.group(1)
                        elif os1_compile.match(line):
                            my_match = os1_compile.match(line)
                            host_info_dic[host_ip]['os'] = my_match.group(1)
                        elif os2_compile.match(line):
                            if not host_info_dic[host_ip]['os']:
                                my_match = os2_compile.match(line)
                                host_info_dic[host_ip]['os'] = my_match.group(1)
                        elif cpu_architecture_compile.match(line):
                            my_match = cpu_architecture_compile.match(line)
                            host_info_dic[host_ip]['cpu_architecture'] = my_match.group(1)
                        elif cpu_thread_compile.match(line):
                            my_match = cpu_thread_compile.match(line)
                            host_info_dic[host_ip]['cpu_thread'] = int(my_match.group(1))
                        elif thread_per_core_compile.match(line):
                            my_match = thread_per_core_compile.match(line)
                            host_info_dic[host_ip]['thread_per_core'] = int(my_match.group(1))
                        elif cpu_model_compile.match(line):
                            my_match = cpu_model_compile.match(line)
                            host_info_dic[host_ip]['cpu_model'] = my_match.group(1)
                        elif cpu_frequency_compile.match(line):
                            my_match = cpu_frequency_compile.match(line)
                            host_info_dic[host_ip]['cpu_frequency'] = round(float(my_match.group(1))/1000, 1)
                        elif mem_size_compile.match(line):
                            my_match = mem_size_compile.match(line)
                            host_info_dic[host_ip]['mem_size'] = int(my_match.group(1))
                        elif swap_size_compile.match(line):
                            my_match = swap_size_compile.match(line)
                            host_info_dic[host_ip]['swap_size'] = int(my_match.group(1))

        return host_info_dic

    def update_host_info(self, host_info_dic):
        """
        Get old host_info_dic from self.old_host_info_file.
        If host_info missing on host_info_dic, get it from old host_info_dic.
        """
        old_host_info_dic = {}

        if os.path.exists(self.old_host_info_file):
            with open(self.old_host_info_file, 'r') as OHIF:
                old_host_info_dic = json.loads(OHIF.read())

        if old_host_info_dic:
            for host in host_info_dic.keys():
                if (not host_info_dic[host]['os']) and (host in old_host_info_dic) and old_host_info_dic[host]['os']:
                    common.bprint('Host information is empty for "' + str(host) + '", reset it with old host_info.json file.', indent=4, level='Warning')
                    host_info_dic[host] = old_host_info_dic[host]

        return host_info_dic

    def link_host_info_file(self):
        common.bprint('\n>>> Link current host info file into host_info.json')
        common.bprint('ln -s ' + str(self.current_host_info_file) + ' ' + str(self.latest_host_info_file), indent=4)

        if os.path.exists(self.latest_host_info_file):
            try:
                os.remove(self.latest_host_info_file)
            except Exception as error:
                common.bprint('Failed on removing ' + str(self.latest_host_info_file) + '": ' + str(error), indent=4, level='Error')
                sys.exit(1)

        try:
            os.symlink(self.current_host_info_file, self.latest_host_info_file)
        except Exception as error:
            common.bprint('Failed on Linking "' + str(self.current_host_info_file) + '" into "' + str(self.latest_host_info_file) + '": ' + str(error), indent=4, level='Error')
            sys.exit(1)

    def sample_host_info(self):
        # Clean up self.output_dir.
        self.cleanup()

        # Sample host list information.
        self.sample_host_list_info()

        # Sample host os/cpu/mem information.
        self.sample_host_os_hard_info()

        # Collect host os/cpu/mem information.
        self.collect_host_os_hard_info()

        # Link self.current_host_info_file into self.latest_host_info_file.
        self.link_host_info_file()


################
# Main Process #
################
def main():
    (hosts, groups, user, password, parallel, timeout, output_dir) = read_args()
    my_sample_host_info = SampleHostInfo(hosts, groups, user, password, parallel, timeout, output_dir)
    my_sample_host_info.sample_host_info()


if __name__ == '__main__':
    main()
