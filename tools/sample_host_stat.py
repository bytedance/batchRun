# -*- coding: utf-8 -*-
################################
# File Name   : sample_host_stat.py
# Author      : liyanqing.1987
# Created On  : 2024-12-16 09:30:15
# Description : Used to sample host stat info.
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
                        help='Specify the parallelism for batch_run, default is "0".')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        default=20,
                        help='Specify the timeout for batch_run, default is "20".')
    parser.add_argument('-i', '--host_info_json',
                        default=str(config.db_path) + '/host_info/host_info.json',
                        help='Specify host info file to collect host static information, default is "' + str(config.db_path) + '/host_info/host_info.json".')
    parser.add_argument('-o', '--output_dir',
                        default=str(config.db_path) + '/host_stat',
                        help='Specify host info output directory, default is "' + str(config.db_path) + '/host_stat".')

    args = parser.parse_args()

    # Check and update output_dir.
    if os.path.exists(args.output_dir):
        args.output_dir = os.path.realpath(args.output_dir)
    else:
        common.bprint('"' + str(args.output_dir) + '": No such directory.', level='Error')
        sys.exit(1)

    return args.hosts, args.groups, args.user, args.password, args.parallel, args.timeout, args.host_info_json, args.output_dir


class SampleHostStat():
    def __init__(self, host_list, group_list, user, password, parallel, timeout, host_info_json, output_dir):
        self.host_list = host_list
        self.group_list = group_list
        self.user = user
        self.password = password
        self.parallel = parallel
        self.timeout = timeout
        self.host_info_json = host_info_json
        self.output_dir = output_dir

        self.top_host_stat_file = str(self.output_dir) + '/host_stat.json'
        current_date = datetime.datetime.now().strftime("%Y%m%d")
        current_time = datetime.datetime.now().strftime("%H%M%S")
        self.output_dir = str(self.output_dir) + '/' + str(current_date) + '/' + str(current_time)
        common.create_dir(self.output_dir)
        self.host_stat_file = str(self.output_dir) + '/host_stat.json'

        self.top_host_stat_file = str(config.db_path) + '/host_stat/host_stat.json'

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

    def collect_host_stat(self):
        """
        Collect host stat information from free/top command output files under self.output_dir.
        "df --block-size GB /tmp" command output format:
        ----------------
        Filesystem             1GB-blocks  Used Available Use% Mounted on
        /dev/mapper/centos-tmp     1620GB   1GB    1620GB   1% /tmp
        ----------------

        "free -g" command output format:
        ----------------
                      total        used        free      shared  buff/cache   available
        Mem:           1007          85          18           0         903         919
        Swap:           127          12         115
        ----------------

        "top" command output format:
        ----------------
        top - 14:45:12 up 264 days,  2:54, 89 users,  load average: 2.29, 3.15, 3.14
        Tasks: 1335 total,   1 running, 1330 sleeping,   0 stopped,   4 zombie
        %Cpu(s): 10.5 us,  4.0 sy,  0.0 ni, 84.4 id,  0.8 wa,  0.0 hi,  0.3 si,  0.0 st
        KiB Mem : 13289836+total,   954524 free, 10221516 used, 12172232+buff/cache
        KiB Swap:  8050684 total,  5294412 free,  2756272 used. 11724635+avail Mem

           PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
         17706 root      20   0  174036   3884   1972 R  22.2  0.0   0:00.06 top -bc -n 1
        ----------------
        """
        host_stat_dic = {}

        # Get host_stat_dic based on *.stat files.
        tmp_compile = re.compile(r'^\s*(\S+)\s+(\d+)GB\s+(\d+)GB\s+(\d+)GB\s+(\d+)\%\s+/tmp\s*$$')
        mem_compile = re.compile(r'^\s*Mem:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$')
        swap_compile = re.compile(r'^\s*Swap:\s*(\d+)\s+(\d+)\s+(\d+)\s*$')
        top_compile = re.compile(r'^\s*top .* up\s*((\d+)\s*day(s)?,)?.* (\d+)\s+user(s)?,\s*load\s+average:\s*([0-9\.]+),\s*([0-9\.]+),\s*([0-9\.]+)\s*$')
        tasks_compile = re.compile(r'^\s*Tasks:\s*(\d+)\s*total,\s*(\d+)\s*running,\s*(\d+)\s*sleeping,\s*(\d+)\s*stopped,\s*(\d+)\s*zombie\s*$')
        cpu_compile = re.compile(r'^\s*%Cpu\(s\):\s*([0-9\.]+)\s*us,\s*([0-9\.]+)\s*sy,\s*([0-9\.]+)\s*ni,\s*([0-9\.]+)\s*id,\s*([0-9\.]+)\s*wa,\s*([0-9\.]+)\s*hi,\s*([0-9\.]+)\s*si,\s*([0-9\.]+)\s*st\s*$')

        # Get host host_name/groups info.
        host_info_dic = {}

        if os.path.exists(self.host_info_json):
            with open(self.host_info_json, 'r') as HIJ:
                host_info_dic = json.loads(HIJ.read())

        # Parse host stat file(s).
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if re.match(r'^(\S+)\.stat$', file):
                    my_match = re.match(r'^(\S+)\.stat$', file)
                    host_ip = my_match.group(1)
                    host_stat_dic.setdefault(host_ip, {'host_name': [],
                                                       'groups': [],
                                                       'up_days': 0,
                                                       'users': 0,
                                                       'tasks': 0,
                                                       'r1m': 0.0,
                                                       'r5m': 0.0,
                                                       'r15m': 0.0,
                                                       'cpu_thread': 0,
                                                       'cpu_id': 0.0,
                                                       'cpu_wa': 0.0,
                                                       'mem_total': 0,
                                                       'mem_used': 0,
                                                       'mem_free': 0,
                                                       'mem_shared': 0,
                                                       'mem_buff': 0,
                                                       'mem_avail': 0,
                                                       'swap_total': 0,
                                                       'swap_used': 0,
                                                       'swap_free': 0,
                                                       'tmp_total': 0,
                                                       'tmp_used': 0,
                                                       'tmp_avail': 0})

                    if host_ip in host_info_dic:
                        if 'host_name' in host_info_dic[host_ip]:
                            host_stat_dic[host_ip]['host_name'] = host_info_dic[host_ip]['host_name']

                        if 'groups' in host_info_dic[host_ip]:
                            host_stat_dic[host_ip]['groups'] = host_info_dic[host_ip]['groups']

                        if 'cpu_thread' in host_info_dic[host_ip]:
                            host_stat_dic[host_ip]['cpu_thread'] = host_info_dic[host_ip]['cpu_thread']

                    with open(os.path.join(root, file), 'r') as IF:
                        for line in IF.readlines():
                            if tmp_compile.match(line):
                                my_match = tmp_compile.match(line)
                                host_stat_dic[host_ip]['tmp_total'] = int(my_match.group(2))
                                host_stat_dic[host_ip]['tmp_used'] = int(my_match.group(3))
                                host_stat_dic[host_ip]['tmp_avail'] = int(my_match.group(4))
                            elif mem_compile.match(line):
                                my_match = mem_compile.match(line)
                                host_stat_dic[host_ip]['mem_total'] = int(my_match.group(1))
                                host_stat_dic[host_ip]['mem_used'] = int(my_match.group(2))
                                host_stat_dic[host_ip]['mem_free'] = int(my_match.group(3))
                                host_stat_dic[host_ip]['mem_shared'] = int(my_match.group(4))
                                host_stat_dic[host_ip]['mem_buff'] = int(my_match.group(5))
                                host_stat_dic[host_ip]['mem_avail'] = int(my_match.group(6))
                            elif swap_compile.match(line):
                                my_match = swap_compile.match(line)
                                host_stat_dic[host_ip]['swap_total'] = int(my_match.group(1))
                                host_stat_dic[host_ip]['swap_used'] = int(my_match.group(2))
                                host_stat_dic[host_ip]['swap_free'] = int(my_match.group(3))
                            elif top_compile.match(line):
                                my_match = top_compile.match(line)

                                if my_match.group(1):
                                    host_stat_dic[host_ip]['up_days'] = int(my_match.group(2))

                                host_stat_dic[host_ip]['users'] = int(my_match.group(4))
                                host_stat_dic[host_ip]['r1m'] = float(my_match.group(6))
                                host_stat_dic[host_ip]['r5m'] = float(my_match.group(7))
                                host_stat_dic[host_ip]['r15m'] = float(my_match.group(8))
                            elif tasks_compile.match(line):
                                my_match = tasks_compile.match(line)
                                host_stat_dic[host_ip]['tasks'] = int(my_match.group(1))
                            elif cpu_compile.match(line):
                                my_match = cpu_compile.match(line)
                                host_stat_dic[host_ip]['cpu_id'] = float(my_match.group(4))
                                host_stat_dic[host_ip]['cpu_wa'] = float(my_match.group(5))
                                break

        return host_stat_dic

    def sample_host_stat_info(self, host_list, group_list):
        common.bprint('>>> Sampling host stat information ...')
        sample_command = 'df --block-size GB /tmp; free -g; top -b -n 1 | head -n 3'
        batch_run_command = self.get_batch_run_command(host_list, group_list, self.user, self.password, self.parallel, self.timeout)
        command = str(batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(self.output_dir) + '/HOST.stat'
        common.bprint(command, indent=4)
        os.system(command)

    def get_host_stat(self):
        common.bprint('\n>>> Collecting host stat ...')
        host_stat_dic = self.collect_host_stat()

        with open(self.host_stat_file, 'w') as HIF:
            HIF.write(str(json.dumps(host_stat_dic, ensure_ascii=False, indent=4)) + '\n')

        common.bprint('    Host info has been saved to file "' + str(self.host_stat_file) + '".')

        return host_stat_dic

    def gen_ssh_fail_host_file(self, host_stat_dic, ssh_fail_host_file):
        ssh_fail_host_list = []

        for host_ip in host_stat_dic.keys():
            if host_stat_dic[host_ip]['users'] == 0:
                ssh_fail_host_list.append(host_ip)

        if ssh_fail_host_list:
            with open(ssh_fail_host_file, 'w') as SFHF:
                for host_ip in ssh_fail_host_list:
                    SFHF.write(str(host_ip) + '\n')

    def gen_overload_host_file(self, host_stat_dic, overload_host_file):
        overload_host_list = []

        for host_ip in host_stat_dic.keys():
            if ('cpu_thread' in host_stat_dic[host_ip]) and host_stat_dic[host_ip]['cpu_thread'] and (host_stat_dic[host_ip]['r1m'] >= host_stat_dic[host_ip]['cpu_thread']):
                overload_host_list.append(host_ip)

        if overload_host_list:
            with open(overload_host_file, 'w') as OHF:
                for host_ip in overload_host_list:
                    OHF.write(str(host_ip) + '\n')

    def sample_host_top_info(self, host_list, group_list):
        common.bprint('\n>>> Sampling overload host top information ...')
        sample_command = 'top -bc -n 1 -w 256'
        batch_run_command = self.get_batch_run_command(host_list, group_list, self.user, self.password, self.parallel, self.timeout)
        command = str(batch_run_command) + ' --command "' + str(sample_command) + '" --output_message_level 1 --output_file ' + str(self.output_dir) + '/HOST.top'
        common.bprint(command, indent=4)
        os.system(command)

    def link_host_stat_json(self):
        common.bprint('\n>>> Link host_stat.json to top directory ...')

        if os.path.exists(self.host_stat_file):
            if os.path.lexists(self.top_host_stat_file):
                try:
                    os.remove(self.top_host_stat_file)
                except Exception as error:
                    common.bprint('Failed on removing file "' + str(self.top_host_stat_file) + '": ' + str(error), level='Error')

            try:
                common.bprint('    Link "' + str(self.host_stat_file) + '" into "' + str(self.top_host_stat_file))
                os.symlink(self.host_stat_file, self.top_host_stat_file)
            except Exception as error:
                common.bprint('Failed on linking file "' + str(self.host_stat_file) + '" into "' + str(self.top_host_stat_file) + '": ' + str(error), level='Error')

    def cleanup(self):
        common.bprint('\n>>> Cleaning up <HOST>.stat files ...')
        os.system('rm -f ' + str(self.output_dir) + '/*.stat')

    def sample_host_stat(self):
        # Sample host stat information.
        self.sample_host_stat_info(self.host_list, self.group_list)

        # Collect host stat.
        host_stat_dic = self.get_host_stat()

        # Re-sample host stat information for ssh fail host(s).
        ssh_fail_host_file = str(self.output_dir) + '/ssh_fail_host.list'
        self.gen_ssh_fail_host_file(host_stat_dic, ssh_fail_host_file)

        # Collect top information for overload host(s).
        overload_host_file = str(self.output_dir) + '/overload_host.list'
        self.gen_overload_host_file(host_stat_dic, overload_host_file)

        if os.path.exists(overload_host_file) and (os.path.getsize(overload_host_file) > 0):
            self.sample_host_top_info([overload_host_file, ], [])

        # Link host_stat.json into top directory.
        self.link_host_stat_json()

        # Clean up <host>.stat info file if the r1m is less than specified value.
        self.cleanup()


################
# Main Process #
################
def main():
    (hosts, groups, user, password, parallel, timeout, host_info_json, output_dir) = read_args()
    my_sample_host_stat = SampleHostStat(hosts, groups, user, password, parallel, timeout, host_info_json, output_dir)
    my_sample_host_stat.sample_host_stat()


if __name__ == '__main__':
    main()
