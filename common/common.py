import os
import re
import sys
import subprocess

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common_lsf


def print_error(message):
    """
    Print error message with red color.
    """
    print('\033[1;31m' + str(message) + '\033[0m')


def print_warning(message):
    """
    Print warning message with yellow color.
    """
    print('\033[1;33m' + str(message) + '\033[0m')


def is_ip(input_string):
    if re.match(r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])', input_string):
        return(True)
    else:
        return(False)


def run_command(command, mystdin=subprocess.PIPE, mystdout=subprocess.PIPE, mystderr=subprocess.PIPE, show=None):
    """
    Run system command with subprocess.Popen, get returncode/stdout/stderr.
    """
    SP = subprocess.Popen(command, shell=True, stdin=mystdin, stdout=mystdout, stderr=mystderr)
    (stdout, stderr) = SP.communicate()

    if show:
        if show == 'stdout':
            print(str(stdout, 'utf-8').strip())
        elif show == 'stderr':
            print(str(stderr, 'utf-8').strip())

    return(SP.returncode, stdout, stderr)


class ParseHostList():
    def __init__(self):
        self.host_list_dic = {}
        self.expanded_host_list_dic = {}
        self.host_ip_dic = {}
        self.host_name_dic = {}
        self.group_list = []

        self.check_host_list()
        self.parse_host_list()
        self.expand_host_list_dic()

    def check_host_list(self):
        if not config.HOST_LIST:
            print_error('*Error*: Variable "HOST_LIST" is not defined on batchRun config file "config.py".')
            sys.exit(1)
        else:
            if not os.path.exists(config.HOST_LIST):
                print_error('*Error*: "' + str(config.HOST_LIST) + '": No such host list file on config file "config.py".')
                sys.exit(1)

    def parse_host_list(self):
        """
        self.host_list_dic = {<group>: {'hosts': {<host_ip>: {'host_name': <host_name>, 'ssh_port': <ssh_port>}},
                                        'sub_groups' : [<group>]}}
        self.expanded_host_list_dic = {<group>: {<host_ip>: {'host_name': <host_name>, 'ssh_port': <ssh_port>}}}
        self.host_ip_dic   =   {<host_ip>: {'host_ip': <host_ip>, 'host_name': <host_name>, 'ssh_port': <ssh_port>, 'groups': [<group>]}}
        self.host_name_dic = {<host_name>: {'host_ip': <host_ip>, 'host_name': <host_name>, 'ssh_port': <ssh_port>, 'groups': [<group>]}}
        self.group_list = [group1, group2, ...]
        """
        group = ''

        # Get self.host_list_dic/self.host_ip_dic/self.host_name_dic.
        with open(config.HOST_LIST, 'r') as HF:
            for line in HF.readlines():
                line = line.strip()

                if re.match('^\s*$', line) or re.match('^\s*#.*$', line):
                    continue
                elif re.match('^\s*\[\s*(.+)\s*\]\s*$', line):
                    # Get GROUP setting.
                    my_match = re.match('^\s*\[\s*(.+)\s*\]\s*$', line)
                    group = my_match.group(1)

                    if group:
                        if group not in self.host_list_dic:
                            self.host_list_dic[group] = {}
                            self.group_list.append(group)
                        else:
                            print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                            print_error('*Error*: group "' + str(group) + '" is defined repeatedly.')
                            sys.exit(1)
                    else:
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('*Error*: Empty group setting for below line.')
                        print_error('         ' + str(line))
                        sys.exit(1)
                elif re.match('^\s*([0-9\.]+)\s*(\S+)?\s*(\d+)?\s*(#.*)?\s*$', line):
                    # Get host_ip/host_name/ssh_port setting.
                    my_match = re.match('^\s*([0-9\.]+)\s*(\S+)?\s*(\d+)?\s*(#.*)?\s*$', line)
                    host_ip = my_match.group(1)
                    host_name = my_match.group(2)
                    ssh_port = my_match.group(3)

                    # Make sure it is a valid ip.
                    if not is_ip(host_ip):
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('*Error*: "' + str(host_ip) + '": Invalid host ip.')
                        sys.exit(1)

                    if not group:
                        # Must define group before host_ip.
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('*Error*: group information is missing for host "' + str(host_ip) + '".')
                        sys.exit(1)
                    else:
                        self.host_list_dic[group].setdefault('hosts', {})

                        if host_ip in self.host_list_dic[group]['hosts']:
                            print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                            print_error('*Error*: host "' + str(host_ip) + '" is defined repeatedly on group "' + str(group) + '".')
                            sys.exit(1)
                        else:
                            # Update self.host_list_dic host_ip.
                            self.update_group_host_dic(group, host_ip, host_name, ssh_port)

                            # Update self.host_ip_dic.
                            self.update_host_ip_dic(group, host_ip, host_name, ssh_port)

                            # Update self.host_name_dic.
                            self.update_host_name_dic(group, host_ip, host_name, ssh_port)
                else:
                    if group:
                        self.host_list_dic[group].setdefault('invalid_lines', [])
                        self.host_list_dic[group]['invalid_lines'].append(line)
                    else:
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('         ' + str(line))
                        sys.exit(1)

            # Switch invalid_lines into sub_groups on group setting.
            self.switch_invalid_lines()

            # Make sure self.host_list_dic is not empty.
            if not self.host_list_dic:
                print_error('*Error*: No valid setting on "' + str(config.HOST_LIST) + '".')
                sys.exit(1)

            # Make sure self.host_list_dic group is not empty.
            for group in self.host_list_dic.keys():
                if not self.host_list_dic[group]:
                    print_error('*Error*: group "' + str(group) + '" is empty on "' + str(config.HOST_LIST) + '".')
                    sys.exit(1)

    def update_group_host_dic(self, group, host_ip, host_name, ssh_port):
        self.host_list_dic[group]['hosts'].setdefault(host_ip, {})

        if host_name:
            self.host_list_dic[group]['hosts'][host_ip]['host_name'] = host_name

        if ssh_port:
            self.host_list_dic[group]['hosts'][host_ip]['ssh_port'] = ssh_port

    def update_host_ip_dic(self, group, host_ip, host_name, ssh_port):
        if host_ip not in self.host_ip_dic:
            self.host_ip_dic[host_ip] = {'host_ip': host_ip, 'groups': [group, ]}
        else:
            self.host_ip_dic[host_ip]['groups'].append(group)

        if host_name:
            if 'host_name' in self.host_ip_dic[host_ip]:
                if self.host_ip_dic[host_ip]['host_name'] != host_name:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('*Error*: host "' + str(host_ip) + '" have different hostname "' + str(self.host_ip_dic[host_ip]['host_name']) + '" & "' + str(host_name) + '".')
                    sys.exit(1)
            else:
                self.host_ip_dic[host_ip]['host_name'] = host_name

        if ssh_port:
            if 'ssh_port' in self.host_ip_dic[host_ip]:
                if self.host_ip_dic[host_ip]['ssh_port'] != ssh_port:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('*Error*: host "' + str(host_ip) + '" have different ssh port "' + str(self.host_ip_dic[host_ip]['ssh_port']) + '" & "' + str(ssh_port) + '".')
                    sys.exit(1)
            else:
                self.host_ip_dic[host_ip]['ssh_port'] = ssh_port

    def update_host_name_dic(self, group, host_ip, host_name, ssh_port):
        if host_name:
            if host_name not in self.host_name_dic:
                self.host_name_dic[host_name] = {'host_ip': host_ip, 'host_name': host_name, 'groups': [group, ]}
            else:
                if self.host_name_dic[host_name]['host_ip'] != host_ip:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('*Error*: host "' + str(host_name) + '" have different host ip "' + str(self.host_name_dic[host_name]['host_ip']) + '" & "' + str(host_ip) + '".')
                    sys.exit(1)

            if ssh_port:
                if 'ssh_port' not in self.host_name_dic[host_name]:
                    self.host_name_dic[host_name]['ssh_port'] = ssh_port
                else:
                    if self.host_name_dic[host_name]['ssh_port'] != ssh_port:
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('*Error*: host "' + str(host_name) + '" have different ssh port "' + str(self.host_name_dic[host_ip]['ssh_port']) + '" & "' + str(ssh_port) + '".')
                        sys.exit(1)

    def switch_invalid_lines(self):
        for group in self.host_list_dic.keys():
            if 'invalid_lines' in self.host_list_dic[group]:
                for line in self.host_list_dic[group]['invalid_lines']:
                    for sub_group in line.split():
                        if sub_group not in self.host_list_dic:
                            print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                            print_error('         ' + str(line))
                            sys.exit(1)
                        else:
                            self.host_list_dic[group].setdefault('sub_groups', [])

                            if sub_group not in self.host_list_dic[group]['sub_groups']:
                                self.host_list_dic[group]['sub_groups'].append(sub_group)
                            else:
                                print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                                print_error('*Error*: sub-group "' + str(sub_group) + '" is defined repeatedly on group "' + str(group) + '".')
                                sys.exit(1)

                del self.host_list_dic[group]['invalid_lines']

    def expand_host_list_dic(self):
        for group in self.host_list_dic.keys():
            group_host_dic = self.get_group_host_dic(group)
            self.expanded_host_list_dic[group] = group_host_dic

    def get_group_host_dic(self, group):
        group_host_dic = {}

        if group in self.host_list_dic:
            # Save group hosts into group_host_dic.
            if 'hosts' in self.host_list_dic[group]:
                group_host_dic = self.host_list_dic[group]['hosts']

            # Save group sub-groups hosts into group_host_dic.
            if 'sub_groups' in self.host_list_dic[group]:
                for sub_group in self.host_list_dic[group]['sub_groups']:
                    sub_group_host_dic = self.get_group_host_dic(sub_group)

                    for host_ip in sub_group_host_dic.keys():
                        if host_ip not in group_host_dic:
                            group_host_dic[host_ip] = {}

                            if 'host_name' in sub_group_host_dic[host_ip]:
                                group_host_dic[host_ip]['host_name'] = sub_group_host_dic[host_ip]['host_name']

                            if 'ssh_port' in sub_group_host_dic[host_ip]:
                                group_host_dic[host_ip]['ssh_port'] = sub_group_host_dic[host_ip]['ssh_port']

        return(group_host_dic)


def get_host_ip(host, host_list_class=None):
    if is_ip(host):
        return(host)
    else:
        if not host_list_class:
            host_list_class = ParseHostList()

        for group in host_list_class.expanded_host_list_dic.keys():
            for host_ip in host_list_class.expanded_host_list_dic[group].keys():
                if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip].keys():
                    if host_list_class.expanded_host_list_dic[group][host_ip]['host_name'] == host:
                        return(host_ip)

    return(None)


def get_host_name(host, host_list_class=None):
    if not is_ip(host):
        return(host)
    else:
        if not host_list_class:
            host_list_class = ParseHostList()

        for group in host_list_class.expanded_host_list_dic.keys():
            for host_ip in host_list_class.expanded_host_list_dic[group].keys():
                if host_ip == host:
                    if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip].keys():
                        return(host_list_class.expanded_host_list_dic[group][host_ip]['host_name'])

    return(None)


def check_exclusion(host, excluded_host_list, host_list_class=None):
    if not host_list_class:
        host_list_class = ParseHostList()

    if host in excluded_host_list:
        return(True)
    else:
        if is_ip(host):
            for excluded_host in excluded_host_list:
                if not is_ip(excluded_host):
                    excluded_host_ip = get_host_ip(excluded_host, host_list_class)

                    if excluded_host_ip == host:
                        return(True)
        else:
            for excluded_host in excluded_host_list:
                if is_ip(excluded_host):
                    excluded_host_name = get_host_name(excluded_host, host_list_class)

                    if excluded_host_name == host:
                        return(True)

    return(False)


def check_repetitiveness(host, specified_host_dic):
    if host in specified_host_dic.keys():
        print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
        return(True)
    else:
        if is_ip(host):
            for specified_host in specified_host_dic.keys():
                if not is_ip(specified_host):
                    if 'host_ip' in specified_host_dic[specified_host].keys():
                        if specified_host_dic[specified_host]['host_ip'] == host:
                            print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
                            return(True)
        else:
            for specified_host in specified_host_dic.keys():
                if is_ip(specified_host):
                    if 'host_name' in specified_host_dic[specified_host].keys():
                        if specified_host_dic[specified_host]['host_name'] == host:
                            print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
                            return(True)

    return(False)


def parse_specified_groups(specified_group_list, host_list_class=None, specified_host_dic={}, excluded_host_list=[]):
    if not host_list_class:
        host_list_class = ParseHostList()

    # Get excluded group list.
    excluded_group_list = []
    expected_group_list = []

    for group in specified_group_list:
        if re.match('^~(\S+)$', group):
            my_match = re.match('^~(\S+)$', group)
            excluded_group = my_match.group(1)

            if excluded_group not in host_list_class.expanded_host_list_dic.keys():
                print_error('*Error*: ' + str(group) + ': Invalid host group.')
                sys.exit(1)
            else:
                excluded_group_list.append(excluded_group)
        else:
            if group not in host_list_class.expanded_host_list_dic.keys():
                print_error('*Error*: ' + str(group) + ': Invalid host group.')
                sys.exit(1)
            else:
                expected_group_list.append(group)

    # Get excluded host list.
    for group in excluded_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if host_ip not in excluded_host_list:
                excluded_host_list.append(host_ip)

    # Get specified host dic.
    for group in expected_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if (not check_exclusion(host_ip, excluded_host_list, host_list_class)) and (not check_repetitiveness(host_ip, specified_host_dic)):
                specified_host_dic[host_ip] = {'host_ip': host_ip}

                if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip]:
                    specified_host_dic[host_ip]['host_name'] = host_list_class.expanded_host_list_dic[group][host_ip]['host_name']

                if 'ssh_port' in host_list_class.expanded_host_list_dic[group][host_ip]:
                    specified_host_dic[host_ip]['ssh_port'] = host_list_class.expanded_host_list_dic[group][host_ip]['ssh_port']

    return(specified_host_dic, excluded_host_list)


def parse_specified_hosts(specified_host_list, host_list_class=None, specified_host_dic={}, excluded_host_list=[]):
    if not host_list_class:
        host_list_class = ParseHostList()

    # Get excluded host list.
    for host_string in specified_host_list:
        if re.match('^~(\S+)$', host_string):
            my_match = re.match('^~(\S+)$', host_string)
            excluded_host = my_match.group(1)

            if excluded_host not in excluded_host_list:
                excluded_host_list.append(excluded_host)

    # Parse specified hosts.
    for host_string in specified_host_list:
        if re.match('^~(\S+)$', host_string):
            continue
        elif re.match('^(\S+):(\d+)$', host_string):
            # Parse input host string, get host and ssh_port information.
            my_match = re.match('^(\S+):(\d+)$', host_string)
            host = my_match.group(1)
            ssh_port = my_match.group(2)
        elif re.match('^(\S+)$', host_string):
            host = host_string
            ssh_port = None
        else:
            print_error('*Error*: "' + str(host_string) + '": Invalid host format.')
            sys.exit(1)

        # Don't process repeated specified host.
        if (not check_exclusion(host, excluded_host_list, host_list_class)) and (not check_repetitiveness(host, specified_host_dic)):
            if host in host_list_class.host_ip_dic:
                # If specify a known host_ip.
                specified_host_dic[host] = host_list_class.host_ip_dic[host]

                # Make sure the ssh_port configuration is consistent.
                if ssh_port:
                    if 'ssh_port' in host_list_class.host_ip_dic[host]:
                        if host_list_class.host_ip_dic[host]['ssh_port'] != ssh_port:
                            print_error('*Error*: for host "' + str(host) + '", specified ssh_port "' + str(ssh_port) + '" is different with configured ssh_port "' + str(host_list_class.host_ip_dic[host]['ssh_port']) + '".')
                            sys.exit(1)
                    else:
                        specified_host_dic[host]['ssh_port'] = ssh_port
            elif host in host_list_class.host_name_dic:
                # If specify a known host_name.
                specified_host_dic[host] = host_list_class.host_name_dic[host]

                # Make sure the ssh_port configuration is consistent.
                if ssh_port:
                    if 'ssh_port' in host_list_class.host_name_dic[host]:
                        if host_list_class.host_name_dic[host]['ssh_port'] != ssh_port:
                            print_error('*Error*: for host "' + str(host) + '", specified ssh_port "' + str(ssh_port) + '" is different with configured ssh_port "' + str(host_list_class.host_name_dic[host]['ssh_port']) + '".')
                            sys.exit(1)
                    else:
                        specified_host_dic[host]['ssh_port'] = ssh_port
            elif is_ip(host):
                # If specify a unknown host_ip.
                specified_host_dic[host] = {'host_ip': host}

                if ssh_port:
                    specified_host_dic[host]['ssh_port'] = ssh_port
            else:
                host_dic = {}

                # With FUZZY_MATCH mode.
                # If specify a unknown-suspected incomplate host_ip/host_name.
                if config.FUZZY_MATCH:
                    # fuzzy matching host_ip.
                    for host_ip in host_list_class.host_ip_dic.keys():
                        if re.search(host, host_ip):
                            # Match host_ip.
                            print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_ip))

                            specified_host_dic[host_ip] = host_list_class.host_ip_dic[host_ip]
                            host_dic[host_ip] = host_list_class.host_ip_dic[host_ip]

                            # Make sure the ssh_port configuration is consistent.
                            if ssh_port:
                                if 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                                    if host_list_class.host_ip_dic[host_ip]['ssh_port'] != ssh_port:
                                        print_error('*Error*: for host "' + str(host_ip) + '", specified ssh_port "' + str(ssh_port) + '" is different with configured ssh_port "' + str(host_list_class.host_ip_dic[host]['ssh_port']) + '".')
                                        sys.exit(1)
                                else:
                                    specified_host_dic[host]['ssh_port'] = ssh_port
                                    host_dic[host]['ssh_port'] = ssh_port

                    # fuzzy matching host_name.
                    for host_name in host_list_class.host_name_dic.keys():
                        if re.search(host, host_name):
                            # Make sure host_name is not saved repeatedly.
                            continue_mark = False

                            for saved_host in host_dic.keys():
                                if 'host_name' in host_dic[saved_host].keys():
                                    if host_dic[saved_host]['host_name'] == host_name:
                                        continue_mark = True
                                        break

                            if continue_mark:
                                continue

                            # Match hostname.
                            print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_name))

                            specified_host_dic[host_name] = host_list_class.host_name_dic[host_name]
                            host_dic[host_name] = host_list_class.host_name_dic[host_name]

                            # Make sure the ssh_port configuration is consistent.
                            if ssh_port:
                                if 'ssh_port' in host_list_class.host_name_dic[host_name]:
                                    if host_list_class.host_name_dic[host_name]['ssh_port'] != ssh_port:
                                        print_error('*Error*: for host "' + str(host_name) + '", specified ssh_port "' + str(ssh_port) + '" is different with configured ssh_port "' + str(host_list_class.host_name_dic[host]['ssh_port']) + '".')
                                        sys.exit(1)
                                else:
                                    specified_host_dic[host]['ssh_port'] = ssh_port
                                    host_dic[host]['ssh_port'] = ssh_port

                if not host_dic:
                    # If specify a unknown-suspected host_name.
                    specified_host_dic[host] = {'host_name': host}

                    if ssh_port:
                        specified_host_dic[host]['ssh_port'] = ssh_port

    return(specified_host_dic, excluded_host_list)


def parse_specified_lsf_queues(specified_lsf_queue_list, host_list_class=None, queue_host_dic={}, specified_host_dic={}, excluded_host_list=[]):
    if not host_list_class:
        host_list_class = ParseHostList()

    if not queue_host_dic:
        queue_host_dic = common_lsf.get_queue_host_info()

    # Get excluded lsf queue list.
    excluded_queue_list = []
    expected_queue_list = []

    for queue in specified_lsf_queue_list:
        if re.match('^~(\S+)$', queue):
            my_match = re.match('^~(\S+)$', queue)
            excluded_queue = my_match.group(1)

            if excluded_queue not in queue_host_dic.keys():
                print_error('*Error*: ' + str(excluded_queue) + ': Invalid LSF queue.')
                sys.exit(1)
            else:
                excluded_queue_list.append(excluded_queue)
        else:
            if queue not in queue_host_dic.keys():
                print_error('*Error*: ' + str(queue) + ': Invalid LSF queue.')
                sys.exit(1)
            else:
                expected_queue_list.append(queue)

    # Get exclued host list.
    for queue in excluded_queue_list:
        for host in queue_host_dic[queue]:
            if host not in excluded_host_list:
                excluded_host_list.append(host)

    # Get specified host dic.
    for queue in expected_queue_list:
        for host_name in queue_host_dic[queue]:
            if (not check_exclusion(host_name, excluded_host_list, host_list_class)) and (not check_repetitiveness(host_name, specified_host_dic)):
                specified_host_dic[host_name] = {'host_name': host_name}
                host_ip = get_host_ip(host_name)

                if host_ip:
                    specified_host_dic[host_name]['host_ip'] = host_ip

                    for group in host_list_class.expanded_host_list_dic.keys():
                        for ip in host_list_class.expanded_host_list_dic[group].keys():
                            if ip == host_ip:
                                if 'ssh_port' in host_list_class.expanded_host_list_dic[group][host_ip]:
                                    specified_host_dic[host_name]['ssh_port'] = host_list_class.expanded_host_list_dic[group][host_ip]['ssh_port']

    return(specified_host_dic, excluded_host_list)
