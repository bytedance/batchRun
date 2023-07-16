import os
import re
import sys
import subprocess
import copy

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
    """
    Judge the input string is ip or not.
    """
    if re.match(r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])', input_string):
        return True
    else:
        return False


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

    return (SP.returncode, stdout, stderr)


class ParseHostList():
    """
    Parse config.HOST_LIST, get group/host_ip/host_name related information.
    """
    def __init__(self):
        self.host_list_dic = {}
        self.expanded_host_list_dic = {}
        self.host_ip_dic = {}
        self.host_name_dic = {}

        self.check_host_list()
        self.parse_host_list()
        self.expand_host_list_dic()

    def check_host_list(self):
        """
        Make sure config.HOST_LIST is defined and the file exists.
        """
        if not config.HOST_LIST:
            print_error('*Error*: Variable "HOST_LIST" is not defined on batchRun config file "config.py".')
            sys.exit(1)
        else:
            if not os.path.exists(config.HOST_LIST):
                print_error('*Error*: "' + str(config.HOST_LIST) + '": No such host list file on config file "config.py".')
                sys.exit(1)

    def parse_host_list(self):
        """
        # self.host_list_dic is used to save original information.
        self.host_list_dic = {<group>: {'hosts': {<host_ip>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>}},
                                        'sub_groups': [<group>,]},
                                        'exclude_hosts': {'host_ip': [<host_ip>,], 'host_name': [<host_name>,]},
                                        'exclude_groups': [<group>,]}
                                        'unknown_lines': [<line>,]}

        # self.expanded_host_list_dic is used to save expanded group-ip information.
        self.expanded_host_list_dic = {<group>: {<host_ip>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>}}}

        # self.host_ip_dic is used to save host_ip information.
        self.host_ip_dic = {<host_ip>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}

        # self.host_name_dic is used to save host_name information.
        self.host_name_dic = {<host_name>: {'host_ip': [<host_ip>,]}}
        """
        group = ''

        # Get self.host_list_dic/self.host_ip_dic/self.host_name_dic.
        with open(config.HOST_LIST, 'r') as HF:
            for line in HF.readlines():
                line = line.strip()

                if re.match(r'^\s*$', line) or re.match(r'^\s*#.*$', line):
                    continue
                elif re.match(r'^\s*\[\s*(.+)\s*\]\s*$', line):
                    # Get GROUP setting.
                    my_match = re.match(r'^\s*\[\s*(.+)\s*\]\s*$', line)
                    group = my_match.group(1)

                    if group:
                        if group not in self.host_list_dic:
                            self.host_list_dic[group] = {}
                        else:
                            print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                            print_error('         Group "' + str(group) + '" is defined repeatedly.')
                            sys.exit(1)
                    else:
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('         Empty group setting for below line.')
                        print_error('         ' + str(line))
                        sys.exit(1)
                elif re.match(r'^\s*([0-9\.]+)\s*(\S+)?\s*(\d+)?\s*(#.*)?\s*$', line):
                    # Get host_ip/host_name/ssh_port setting.
                    my_match = re.match(r'^\s*([0-9\.]+)\s*(\S+)?\s*(\d+)?\s*(#.*)?\s*$', line)
                    host_ip = my_match.group(1)
                    host_name = my_match.group(2)
                    ssh_port = my_match.group(3)

                    # Make sure it is a valid ip.
                    if not is_ip(host_ip):
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('         "' + str(host_ip) + '": Invalid host ip.')
                        sys.exit(1)

                    if not group:
                        # Must define group before host_ip.
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('         Group information is missing for host "' + str(host_ip) + '".')
                        sys.exit(1)
                    else:
                        # Update self.host_list_dic host_ip.
                        self.update_group_hosts_dic(group, host_ip, host_name, ssh_port)

                        # Update self.host_ip_dic.
                        self.update_host_ip_dic(group, host_ip, host_name, ssh_port)

                        # Update self.host_name_dic.
                        self.update_host_name_dic(host_ip, host_name)
                else:
                    if group:
                        self.host_list_dic[group].setdefault('unknown_lines', [])
                        self.host_list_dic[group]['unknown_lines'].append(line)
                    else:
                        print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                        print_error('         ' + str(line))
                        sys.exit(1)

            # Switch unknown_lines into sub_groups on group setting.
            self.switch_unknown_lines()

            # Make sure self.host_list_dic is not empty.
            if not self.host_list_dic:
                print_error('*Error*: No valid setting on "' + str(config.HOST_LIST) + '".')
                sys.exit(1)

            # Make sure self.host_list_dic group is not empty.
            for group in self.host_list_dic:
                if not self.host_list_dic[group]:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('         Group "' + str(group) + '" is empty on "' + str(config.HOST_LIST) + '".')
                    sys.exit(1)

    def update_group_hosts_dic(self, group, host_ip, host_name, ssh_port):
        """
        Update self.host_list_dic[group]['hosts']
        """
        self.host_list_dic[group].setdefault('hosts', {})
        self.host_list_dic[group]['hosts'].setdefault(host_ip, {})

        # Update host_name.
        if host_name:
            if 'host_name' not in self.host_list_dic[group]['hosts'][host_ip]:
                self.host_list_dic[group]['hosts'][host_ip]['host_name'] = [host_name,]
            else:
                if host_name not in self.host_list_dic[group]['hosts'][host_ip]['host_name']:
                    self.host_list_dic[group]['hosts'][host_ip]['host_name'].append(host_name)
                else:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('         host_ip "' + str(host_ip) + '" & host_name "' + str(host_name) + '" is defined repeatedly.')
                    sys.exit(1)

        # Update ssh_port.
        if ssh_port:
            if 'ssh_port' not in self.host_list_dic[group]['hosts'][host_ip]:
                self.host_list_dic[group]['hosts'][host_ip]['ssh_port'] = ssh_port
            else:
                if self.host_list_dic[group]['hosts'][host_ip]['ssh_port'] != ssh_port:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('         Host "' + str(host_ip) + '" have different ssh port "' + str(self.host_list_dic[group]['hosts'][host_ip]['ssh_port']) + '" & "' + str(ssh_port) + '".')
                    sys.exit(1)

    def update_host_ip_dic(self, group, host_ip, host_name, ssh_port):
        """
        Update self.host_ip_dic.
        """
        # Update groups.
        if host_ip not in self.host_ip_dic:
            self.host_ip_dic[host_ip] = {'groups': [group,]}
        else:
            self.host_ip_dic[host_ip]['groups'].append(group)

        # Update host_name.
        if host_name:
            if 'host_name' not in self.host_ip_dic[host_ip]:
                self.host_ip_dic[host_ip]['host_name'] = [host_name,]
            else:
                if host_name not in self.host_ip_dic[host_ip]['host_name']:
                    self.host_ip_dic[host_ip]['host_name'].append(host_name)

        # Update ssh_port.
        if ssh_port:
            if 'ssh_port' not in self.host_ip_dic[host_ip]:
                self.host_ip_dic[host_ip]['ssh_port'] = ssh_port
            else:
                if self.host_ip_dic[host_ip]['ssh_port'] != ssh_port:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('         Host "' + str(host_ip) + '" have different ssh port "' + str(self.host_ip_dic[host_ip]['ssh_port']) + '" & "' + str(ssh_port) + '".')
                    sys.exit(1)

    def update_host_name_dic(self, host_ip, host_name):
        """
        Update self.host_name_dic.
        """
        # Update host_ip.
        self.host_name_dic.setdefault(host_name, {})

        if host_ip:
            if 'host_ip' not in self.host_name_dic[host_name]:
                self.host_name_dic[host_name]['host_ip'] = [host_ip,]
            else:
                if host_ip not in self.host_name_dic[host_name]['host_ip']:
                    self.host_name_dic[host_name]['host_ip'].append(host_ip)

    def switch_unknown_lines(self):
        """
        Judge and process "unknown" lines.
        It could be sub-group setting or exclude host/group setting.
        """
        for group in self.host_list_dic:
            if 'unknown_lines' in self.host_list_dic[group]:
                for line in self.host_list_dic[group]['unknown_lines']:
                    if re.match(r'^\s*~\s*(\S+)\s*$', line):
                        # For excluded group/host_ip/host_name.
                        my_match = re.match(r'^\s*~\s*(\S+)\s*$', line)
                        exclude_item = my_match.group(1)

                        if exclude_item in self.host_list_dic:
                            # If match group.
                            self.host_list_dic[group].setdefault('exclude_groups', [])

                            if exclude_item not in self.host_list_dic[group]['exclude_groups']:
                                self.host_list_dic[group]['exclude_groups'].append(exclude_item)
                        elif exclude_item in self.host_ip_dic:
                            # If match host_ip.
                            self.host_list_dic[group].setdefault('exclude_hosts', {})
                            self.host_list_dic[group]['exclude_hosts'].setdefault('host_ip', [])

                            if exclude_item not in self.host_list_dic[group]['exclude_hosts']['host_ip']:
                                self.host_list_dic[group]['exclude_hosts']['host_ip'].append(exclude_item)
                        elif exclude_item in self.host_name_dic:
                            # If match host_name.
                            self.host_list_dic[group].setdefault('exclude_hosts', {})
                            self.host_list_dic[group]['exclude_hosts'].setdefault('host_name', [])

                            if exclude_item not in self.host_list_dic[group]['exclude_hosts']['host_name']:
                                self.host_list_dic[group]['exclude_hosts']['host_name'].append(exclude_item)
                        else:
                            print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '", it could only exclude group/host_ip/host_name.')
                            print_error('         ' + str(line))
                            sys.exit(1)
                    else:
                        # For sub_group.
                        sub_group = line

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
                                print_error('         Sub-group "' + str(sub_group) + '" is defined repeatedly on group "' + str(group) + '".')
                                sys.exit(1)

    def expand_host_list_dic(self):
        """
        Expand group setting on self.host_list_dic, get self.expanded_host_list_dic.
        """
        for group in self.host_list_dic:
            group_hosts_dic = self.get_group_hosts_dic(group)
            self.expanded_host_list_dic[group] = group_hosts_dic

    def get_group_hosts_dic(self, group):
        """
        Expand group setting to host_ip setting.
        """
        group_hosts_dic = {}

        if group in self.host_list_dic:
            # Save group "hosts" into group_hosts_dic.
            if 'hosts' in self.host_list_dic[group]:
                group_hosts_dic = copy.deepcopy(self.host_list_dic[group]['hosts'])

            # Save group "sub_groups" hosts into group_hosts_dic.
            if 'sub_groups' in self.host_list_dic[group]:
                for sub_group in self.host_list_dic[group]['sub_groups']:
                    sub_group_hosts_dic = self.get_group_hosts_dic(sub_group)

                    for host_ip in sub_group_hosts_dic:
                        if host_ip in group_hosts_dic:
                            if ('host_name' in sub_group_hosts_dic[host_ip]) and ('host_name' in group_hosts_dic[host_ip]):
                                group_hosts_dic[host_ip]['host_name'] = list(set(group_hosts_dic[host_ip]['host_name']).union(set(sub_group_hosts_dic[host_ip]['host_name'])))
                        else:
                            group_hosts_dic[host_ip] = sub_group_hosts_dic[host_ip]

            # Exclude group "exclude_hosts" from group_hosts_dic.
            if 'exclude_hosts' in self.host_list_dic[group]:
                if 'host_ip' in self.host_list_dic[group]['exclude_hosts']:
                    for exclude_host_ip in self.host_list_dic[group]['exclude_hosts']['host_ip']:
                        if exclude_host_ip in group_hosts_dic:
                            del group_hosts_dic[exclude_host_ip]

                if 'host_name' in self.host_list_dic[group]['exclude_hosts']:
                    for exclude_host_name in self.host_list_dic[group]['exclude_hosts']['host_name']:
                        group_host_ip_list = list(group_hosts_dic.keys())

                        for host_ip in group_host_ip_list:
                            if ('host_name' in group_hosts_dic[host_ip]) and (exclude_host_name in group_hosts_dic[host_ip]['host_name']):
                                del group_hosts_dic[host_ip]

            # Exclude group "exclude_groups" from group_hosts_dic
            if 'exclude_groups' in self.host_list_dic[group]:
                for exclude_group in self.host_list_dic[group]['exclude_groups']:
                    exclude_group_hosts_dic = self.get_group_hosts_dic(exclude_group)

                    for host_ip in exclude_group_hosts_dic:
                        if host_ip in group_hosts_dic:
                            del group_hosts_dic[host_ip]

        return group_hosts_dic


def get_host_ip(host, host_list_class=None):
    """
    Input "host" could be host_ip or host_name, switch it into valid host_ip.
    """
    if is_ip(host):
        return host
    else:
        if not host_list_class:
            host_list_class = ParseHostList()

        for group in host_list_class.expanded_host_list_dic:
            for host_ip in host_list_class.expanded_host_list_dic[group]:
                if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip]:
                    if host in host_list_class.expanded_host_list_dic[group][host_ip]['host_name']:
                        return host_ip

    return None


def get_host_name(host, host_list_class=None):
    """
    Input "host" could be host_ip or host_name, switch it into valid host_name (if exists).
    """
    if not is_ip(host):
        return host
    else:
        if not host_list_class:
            host_list_class = ParseHostList()

        for group in host_list_class.expanded_host_list_dic:
            for host_ip in host_list_class.expanded_host_list_dic[group]:
                if host_ip == host:
                    if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip]:
                        return (host_list_class.expanded_host_list_dic[group][host_ip]['host_name'])

    return None


def check_exclusion(host, excluded_host_dic, host_list_class=None):
    """
    Check specified host is excluded or not, return True if it is excluded.
    """
    if not host_list_class:
        host_list_class = ParseHostList()

    if not is_ip(host):
        if host in excluded_host_dic:
            return True

    return False


def check_repetitiveness(host, specified_host_dic):
    """
    Check specified host is specified repeated or not, return True if it is specified repeated.
    """
    if host in specified_host_dic:
        print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
        return True
    else:
        if is_ip(host):
            for specified_host in specified_host_dic:
                if not is_ip(specified_host):
                    if 'host_ip' in specified_host_dic[specified_host]:
                        if host in specified_host_dic[specified_host]['host_ip']:
                            print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')

                            return True
        else:
            for specified_host in specified_host_dic.keys():
                if is_ip(specified_host):
                    if 'host_name' in specified_host_dic[specified_host]:
                        if host in specified_host_dic[specified_host]['host_name']:
                            print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')

                            return True

    return False


def parse_specified_groups(specified_group_list, host_list_class=None, specified_host_dic={}, excluded_host_dic={}):
    """
    Get expected hosts and excluded hosts from specified group(s).
    """
    if not host_list_class:
        host_list_class = ParseHostList()

    # Get excluded group list.
    excluded_group_list = []
    expected_group_list = []

    for group in specified_group_list:
        if re.match(r'^~(\S+)$', group):
            my_match = re.match(r'^~(\S+)$', group)
            excluded_group = my_match.group(1)

            if excluded_group not in host_list_class.expanded_host_list_dic:
                print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                print_error('         ' + str(group) + ': Invalid host group.')
                sys.exit(1)
            else:
                excluded_group_list.append(excluded_group)
        else:
            if group not in host_list_class.expanded_host_list_dic:
                print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                print_error('         ' + str(group) + ': Invalid host group.')
                sys.exit(1)
            else:
                expected_group_list.append(group)

    # Get excluded host list.
    for group in excluded_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if host_ip not in excluded_host_dic:
                excluded_host_dic[host_ip] = {}

                if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip]:
                    excluded_host_dic[host_ip]['host_name'] = host_list_class.expanded_host_list_dic[group][host_ip]['host_name']
            else:
                if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip] and 'host_name' in excluded_host_dic[host_ip]:
                    excluded_host_dic[host_ip]['host_name'] = list(set(set(host_list_class.expanded_host_list_dic[group][host_ip]['host_name']).union(set(excluded_host_dic[host_ip]['host_name']))))

    # Get specified host dic.
    for group in expected_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if (not check_exclusion(host_ip, excluded_host_dic, host_list_class)) and (not check_repetitiveness(host_ip, specified_host_dic)):
                specified_host_dic[host_ip] = {'host_ip': [host_ip, ]}

                if 'host_name' in host_list_class.expanded_host_list_dic[group][host_ip]:
                    specified_host_dic[host_ip]['host_name'] = host_list_class.expanded_host_list_dic[group][host_ip]['host_name']

                if 'ssh_port' in host_list_class.expanded_host_list_dic[group][host_ip]:
                    specified_host_dic[host_ip]['ssh_port'] = host_list_class.expanded_host_list_dic[group][host_ip]['ssh_port']

    return (specified_host_dic, excluded_host_dic)


def parse_specified_hosts(specified_host_list, host_list_class=None, specified_host_dic={}, excluded_host_dic={}):
    """
    Get expected hosts and excluded hosts from specified host(s).
    """
    if not host_list_class:
        host_list_class = ParseHostList()

    # Get excluded host list.
    for host_string in specified_host_list:
        if re.match(r'^~(\S+)$', host_string):
            my_match = re.match(r'^~(\S+)$', host_string)
            excluded_host = my_match.group(1)

            if excluded_host not in excluded_host_dic:
                if is_ip(excluded_host):
                    if excluded_host in host_list_class.host_ip_dic:
                        excluded_host_dic[excluded_host] = host_list_class.host_ip_dic[excluded_host]
                    else:
                        excluded_host_dic[excluded_host] = {'host_name': []}
                else:
                    excluded_host_dic[excluded_host] = {}

    # Parse specified hosts.
    for host_string in specified_host_list:
        if re.match(r'^~(\S+)$', host_string):
            continue
        elif re.match(r'^(\S+):(\d+)$', host_string):
            # Parse input host string, get host and ssh_port information.
            my_match = re.match(r'^(\S+):(\d+)$', host_string)
            host = my_match.group(1)
            ssh_port = my_match.group(2)
        elif re.match(r'^(\S+)$', host_string):
            host = host_string
            ssh_port = None
        else:
            print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
            print_error('         ' + str(host_string) + ': Invalid host format.')
            sys.exit(1)

        # Don't process repeated specified host.
        if (not check_exclusion(host, excluded_host_dic, host_list_class)) and (not check_repetitiveness(host, specified_host_dic)):
            if host in host_list_class.host_ip_dic:
                # If specify a known host_ip.
                host_info_dic = {'host_ip': [host, ], 'host_name': host_list_class.host_ip_dic[host]['host_name']}

                # Make sure the ssh_port configuration is consistent.
                if 'ssh_port' in host_list_class.host_ip_dic[host] and ssh_port:
                    if ssh_port != host_list_class.host_ip_dic[host]['ssh_port']:
                        continue
                elif ssh_port:
                    host_info_dic['ssh_port'] = ssh_port
                elif 'ssh_port' in host_list_class.host_ip_dic[host]:
                    host_info_dic['ssh_port'] = host_list_class.host_ip_dic[host]['ssh_port']

                specified_host_dic[host] = host_info_dic
            elif host in host_list_class.host_name_dic:
                # If specify a known host_name.
                if 'host_ip' in host_list_class.host_name_dic[host]:
                    for host_ip in host_list_class.host_name_dic[host]['host_ip']:
                        if host_ip not in specified_host_dic and host_ip in host_list_class.host_ip_dic:
                            host_info_dic = {'host_ip': [host_ip, ], 'host_name': [host, ]}

                            # Make sure the ssh_port configuration is consistent.
                            if 'ssh_port' in host_list_class.host_ip_dic[host_ip] and ssh_port:
                                if ssh_port != host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                    continue
                            elif ssh_port:
                                host_info_dic['ssh_port'] = ssh_port
                            elif 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                                host_info_dic['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']

                            specified_host_dic[host_ip] = host_info_dic
                        else:
                            specified_host_dic[host_ip]['host_name'].append(host)
                            print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
            elif is_ip(host):
                # If specify a unknown host_ip.
                specified_host_dic[host] = {'host_ip': [host, ]}

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
                            # generator host_ip_dic
                            host_info_dic = {'host_ip': [host_ip, ], 'host_name': host_list_class.host_ip_dic[host_ip]['host_name']}

                            print("")

                            # Make sure the ssh_port configuration is consistent.
                            if 'ssh_port' in host_list_class.host_ip_dic[host_ip] and ssh_port:
                                if ssh_port != host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                    continue
                            elif ssh_port:
                                host_info_dic['ssh_port'] = ssh_port
                            elif 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                                host_info_dic['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']

                            # Match host_ip.
                            print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_ip))

                            specified_host_dic[host_ip] = host_info_dic
                            host_dic[host_ip] = host_info_dic

                    # fuzzy matching host_name.
                    for host_name in host_list_class.host_name_dic.keys():
                        if re.search(host, host_name):
                            # Make sure host_name is not saved repeatedly
                            host_ip_list = host_list_class.host_name_dic[host_name]['host_ip']
                            diff_list = list(set(host_ip_list).difference(set(host_dic.keys())))

                            if not diff_list:
                                continue

                            if 'host_ip' in host_list_class.host_name_dic[host_name]:
                                for host_ip in host_list_class.host_name_dic[host_name]['host_ip']:
                                    if host_ip in specified_host_dic:
                                        specified_host_dic[host_ip]['host_name'].append(host_name)
                                        host_dic[host_ip]['host_name'].append(host_name)
                                        print_warning('*Waring*: host "' + str(host) + '" is specified repeatedly.')
                                    else:
                                        host_info_dic = {'host_ip': [host_ip, ], 'host_name': [host_name, ]}

                                        # Make sure the ssh_port configuration is consistent.
                                        if 'ssh_port' in host_list_class.host_ip_dic[host_ip] and ssh_port:
                                            if ssh_port != host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                                continue
                                        elif ssh_port:
                                            host_info_dic['ssh_port'] = ssh_port
                                        elif 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                                            host_info_dic['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']

                                        # Match host_ip.
                                        print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_ip))

                                        specified_host_dic[host_ip] = host_info_dic
                                        host_dic[host_ip] = host_info_dic

                if not host_dic:
                    # If specify a unknown-suspected host_name.
                    specified_host_dic[host] = {'host_name': [host, ]}

                    if ssh_port:
                        specified_host_dic[host]['ssh_port'] = ssh_port

    return (specified_host_dic, excluded_host_dic)


def parse_specified_lsf_queues(specified_lsf_queue_list, host_list_class=None, queue_host_dic={}, specified_host_dic={}, excluded_host_dic={}):
    """
    Get expected hosts and excluded hosts from specified LSF queue(s).
    """
    if not host_list_class:
        host_list_class = ParseHostList()

    if not queue_host_dic:
        queue_host_dic = common_lsf.get_queue_host_info()

    # Get excluded lsf queue list.
    excluded_queue_list = []
    expected_queue_list = []

    for queue in specified_lsf_queue_list:
        if re.match(r'^~(\S+)$', queue):
            my_match = re.match(r'^~(\S+)$', queue)
            excluded_queue = my_match.group(1)

            if excluded_queue not in queue_host_dic:
                print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                print_error('         ' + str(excluded_queue) + ': Invalid LSF queue.')
                sys.exit(1)
            else:
                excluded_queue_list.append(excluded_queue)
        else:
            if queue not in queue_host_dic:
                print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                print_error('         ' + str(queue) + ': Invalid LSF queue.')
                sys.exit(1)
            else:
                expected_queue_list.append(queue)

    # Get exclued host list.
    for queue in excluded_queue_list:
        for excluded_host in queue_host_dic[queue]:
            if excluded_host not in excluded_host_dic:
                if is_ip(excluded_host):
                    if excluded_host in host_list_class.host_ip_dic:
                        excluded_host_dic[excluded_host] = host_list_class.host_ip_dic[excluded_host]
                    else:
                        excluded_host_dic[excluded_host] = {'host_name': []}
                else:
                    excluded_host_dic[excluded_host] = {}

    # Get specified host dic.
    for queue in expected_queue_list:
        for host_name in queue_host_dic[queue]:
            if (not check_exclusion(host_name, excluded_host_dic, host_list_class)) and (not check_repetitiveness(host_name, specified_host_dic)):
                host_ip = get_host_ip(host_name)

                if host_ip:
                    if host_ip not in specified_host_dic:
                        host_info = {'host_name': [host_name, ], 'host_ip': [host_ip, ]}
                        specified_host_dic[host_ip] = host_info
                    else:
                        specified_host_dic[host_ip]['host_name'].append(host_name)

                    for group in host_list_class.expanded_host_list_dic.keys():
                        for ip in host_list_class.expanded_host_list_dic[group].keys():
                            if ip == host_ip:
                                if 'ssh_port' in host_list_class.expanded_host_list_dic[group][host_ip]:
                                    specified_host_dic[host_name]['ssh_port'] = host_list_class.expanded_host_list_dic[group][host_ip]['ssh_port']
                else:
                    host_append_flag = True

                    for host_key in specified_host_dic.keys():
                        if 'host_name' in specified_host_dic[host_key]:
                            if host_name in specified_host_dic[host_key]['host_name']:
                                host_append_flag = False

                    if host_append_flag:
                        specified_host_dic[host_name] = {'host_name': [host_name, ]}
                    else:
                        print_warning('*Waring*: host "' + str(host_name) + '" is specified repeatedly.')

    return (specified_host_dic, excluded_host_dic)
