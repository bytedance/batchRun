import os
import re
import sys
import subprocess
import copy

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config


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
        self.host_name_dic = {<host_name>: [<host_ip>,]}
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
                        if group not in self.host_list_dic.keys():
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
                        self.update_host_list_dic(group, host_ip, host_name, ssh_port)

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
            for group in self.host_list_dic.keys():
                if not self.host_list_dic[group]:
                    print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                    print_error('         Group "' + str(group) + '" is empty on "' + str(config.HOST_LIST) + '".')
                    sys.exit(1)

    def update_host_list_dic(self, group, host_ip, host_name, ssh_port):
        """
        Update self.host_list_dic[group]['hosts']
        """
        self.host_list_dic[group].setdefault('hosts', {})
        self.host_list_dic[group]['hosts'].setdefault(host_ip, {})

        # Update host_name.
        if host_name:
            if 'host_name' not in self.host_list_dic[group]['hosts'][host_ip].keys():
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
            if 'ssh_port' not in self.host_list_dic[group]['hosts'][host_ip].keys():
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
        if host_ip not in self.host_ip_dic.keys():
            self.host_ip_dic[host_ip] = {'groups': [group,]}
        else:
            self.host_ip_dic[host_ip]['groups'].append(group)

        # Update host_name.
        if host_name:
            if 'host_name' not in self.host_ip_dic[host_ip].keys():
                self.host_ip_dic[host_ip]['host_name'] = [host_name,]
            else:
                if host_name not in self.host_ip_dic[host_ip]['host_name']:
                    self.host_ip_dic[host_ip]['host_name'].append(host_name)

        # Update ssh_port.
        if ssh_port:
            if 'ssh_port' not in self.host_ip_dic[host_ip].keys():
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
        if host_name:
            self.host_name_dic.setdefault(host_name, [])

            if host_ip not in self.host_name_dic[host_name]:
                self.host_name_dic[host_name].append(host_ip)

    def switch_unknown_lines(self):
        """
        Judge and process "unknown" lines.
        It could be sub-group setting or exclude host/group setting.
        """
        for group in self.host_list_dic.keys():
            if 'unknown_lines' in self.host_list_dic[group].keys():
                for line in self.host_list_dic[group]['unknown_lines']:
                    if re.match(r'^\s*~\s*(\S+)\s*$', line):
                        # For excluded group/host_ip/host_name.
                        my_match = re.match(r'^\s*~\s*(\S+)\s*$', line)
                        exclude_item = my_match.group(1)

                        if exclude_item in self.host_list_dic.keys():
                            # If match group.
                            self.host_list_dic[group].setdefault('exclude_groups', [])

                            if exclude_item not in self.host_list_dic[group]['exclude_groups']:
                                self.host_list_dic[group]['exclude_groups'].append(exclude_item)
                        elif exclude_item in self.host_ip_dic.keys():
                            # If match host_ip.
                            self.host_list_dic[group].setdefault('exclude_hosts', {})
                            self.host_list_dic[group]['exclude_hosts'].setdefault('host_ip', [])

                            if exclude_item not in self.host_list_dic[group]['exclude_hosts']['host_ip']:
                                self.host_list_dic[group]['exclude_hosts']['host_ip'].append(exclude_item)
                        elif exclude_item in self.host_name_dic.keys():
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

                        if sub_group not in self.host_list_dic.keys():
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
        for group in self.host_list_dic.keys():
            group_hosts_dic = self.get_group_hosts_dic(group)
            self.expanded_host_list_dic[group] = group_hosts_dic

    def get_group_hosts_dic(self, group):
        """
        Expand group setting to host_ip setting.
        """
        group_hosts_dic = {}

        if group in self.host_list_dic.keys():
            # Save group "hosts" into group_hosts_dic.
            if 'hosts' in self.host_list_dic[group].keys():
                group_hosts_dic = copy.deepcopy(self.host_list_dic[group]['hosts'])

            # Save group "sub_groups" hosts into group_hosts_dic.
            if 'sub_groups' in self.host_list_dic[group].keys():
                for sub_group in self.host_list_dic[group]['sub_groups']:
                    sub_group_hosts_dic = self.get_group_hosts_dic(sub_group)

                    for host_ip in sub_group_hosts_dic.keys():
                        if host_ip in group_hosts_dic.keys():
                            if ('host_name' in sub_group_hosts_dic[host_ip].keys()) and ('host_name' in group_hosts_dic[host_ip].keys()):
                                group_hosts_dic[host_ip]['host_name'] = list(set(group_hosts_dic[host_ip]['host_name']).union(set(sub_group_hosts_dic[host_ip]['host_name'])))
                        else:
                            group_hosts_dic[host_ip] = sub_group_hosts_dic[host_ip]

            # Exclude group "exclude_hosts" from group_hosts_dic.
            if 'exclude_hosts' in self.host_list_dic[group].keys():
                if 'host_ip' in self.host_list_dic[group]['exclude_hosts'].keys():
                    for exclude_host_ip in self.host_list_dic[group]['exclude_hosts']['host_ip']:
                        if exclude_host_ip in group_hosts_dic.keys():
                            del group_hosts_dic[exclude_host_ip]

                if 'host_name' in self.host_list_dic[group]['exclude_hosts'].keys():
                    for exclude_host_name in self.host_list_dic[group]['exclude_hosts']['host_name']:
                        group_host_ip_list = list(group_hosts_dic.keys())

                        for host_ip in group_host_ip_list:
                            if ('host_name' in group_hosts_dic[host_ip].keys()) and (exclude_host_name in group_hosts_dic[host_ip]['host_name']):
                                del group_hosts_dic[host_ip]

            # Exclude group "exclude_groups" from group_hosts_dic
            if 'exclude_groups' in self.host_list_dic[group].keys():
                for exclude_group in self.host_list_dic[group]['exclude_groups']:
                    exclude_group_hosts_dic = self.get_group_hosts_dic(exclude_group)

                    for host_ip in exclude_group_hosts_dic.keys():
                        if host_ip in group_hosts_dic.keys():
                            del group_hosts_dic[host_ip]

        return group_hosts_dic


def switch_host_name_to_host_ips(host_name, host_list_class=None):
    """
    Input host_name, output related host_ip list.
    Input "host" could be host_ip or host_name, switch it into valid host_ip list.
    """
    host_ip_list = []

    if not host_list_class:
        host_list_class = ParseHostList()

    if host_name in host_list_class.host_name_dic.keys():
        host_ip_list = host_list_class.host_name_dic[host_name]

    return host_ip_list


def check_repetitiveness(host, specified_host_dic):
    """
    If host in specified_host_dic, return True, else return False.
    """
    if specified_host_dic:
        if host in specified_host_dic.keys():
            return True
        else:
            for specified_host in specified_host_dic.keys():
                if 'host_ip' in specified_host_dic[specified_host].keys():
                    if host in specified_host_dic[specified_host]['host_ip']:
                        return True

    return False


def parse_specified_groups(specified_group_list, host_list_class=None, specified_host_dic={}, excluded_host_list=[]):
    """
    Specified group could be:
    group
    ~group

    Get expected hosts and excluded hosts from specified group(s).
    """
    if not host_list_class:
        host_list_class = ParseHostList()

    # Get expected and excluded group list.
    expected_group_list = []
    excluded_group_list = []

    for group in specified_group_list:
        if re.match(r'^~(\S+)$', group):
            my_match = re.match(r'^~(\S+)$', group)
            excluded_group = my_match.group(1)

            if excluded_group not in host_list_class.expanded_host_list_dic.keys():
                print_error('*Error*: Invalid setting on "' + str(config.HOST_LIST) + '".')
                print_error('         ' + str(group) + ': Invalid host group.')
                sys.exit(1)
            else:
                excluded_group_list.append(excluded_group)
        else:
            if group not in host_list_class.expanded_host_list_dic.keys():
                print_error('*Error*: ' + str(group) + ': Invalid host group.')
                sys.exit(1)
            else:
                expected_group_list.append(group)

    # Get specified host dic.
    for group in expected_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if not check_repetitiveness(host_ip, specified_host_dic):
                specified_host_dic[host_ip] = {}

                if 'ssh_port' in host_list_class.expanded_host_list_dic[group][host_ip].keys():
                    ssh_port = host_list_class.expanded_host_list_dic[group][host_ip]['ssh_port']
                    specified_host_dic[host_ip]['ssh_port'] = ssh_port

    # Get excluded host list.
    for group in excluded_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if host_ip not in excluded_host_list:
                excluded_host_list.append(host_ip)

    return (specified_host_dic, excluded_host_list)


def parse_specified_hosts(specified_host_list, host_list_class=None, specified_host_dic={}, excluded_host_list=[]):
    """
    Specified host could be:
    host_ip
    host_name
    host_ip:ssh_port
    host_name:ssh_port
    ~host_ip
    ~host_name

    Get expected hosts and excluded hosts from specified host(s).
    """
    if not host_list_class:
        host_list_class = ParseHostList()

    # Parse specified hosts.
    for host_string in specified_host_list:
        if re.match(r'^~(\S+)$', host_string):
            host = None
            ssh_port = None

            # Get excluded hosts.
            my_match = re.match(r'^~(\S+)$', host_string)
            excluded_host = my_match.group(1)

            if excluded_host not in excluded_host_list:
                excluded_host_list.append(excluded_host)
        elif re.match(r'^(\S+):(\d+)$', host_string):
            # Parse input host string, get host and ssh_port information.
            my_match = re.match(r'^(\S+):(\d+)$', host_string)
            host = my_match.group(1)
            ssh_port = my_match.group(2)
        elif re.match(r'^(\S+)$', host_string):
            host = host_string
            ssh_port = None
        else:
            print_error('*Error*: ' + str(host_string) + ': Invalid host format.')
            sys.exit(1)

        # Don't process repeated specified host.
        if host and (not check_repetitiveness(host, specified_host_dic)):
            if host in host_list_class.host_ip_dic.keys():
                # If specify a known host_ip.
                specified_host_dic[host] = {}

                if ('ssh_port' in host_list_class.host_ip_dic[host].keys()):
                    if not ssh_port:
                        ssh_port = host_list_class.host_ip_dic[host]['ssh_port']
                    else:
                        if ssh_port != host_list_class.host_ip_dic[host]['ssh_port']:
                            # Make sure the ssh_port configuration is consistent.
                            print_error('*Error*: ' + str(host_string) + ': ssh_port setting is conflict with the sign on "' + str(config.HOST_LIST) + '".')
                            sys.exit(1)

                if ssh_port:
                    specified_host_dic[host]['ssh_port'] = ssh_port
            elif host in host_list_class.host_name_dic.keys():
                # If specify a known host_name.
                for host_ip in host_list_class.host_name_dic[host]:
                    if not check_repetitiveness(host_ip, specified_host_dic):
                        tmp_ssh_port = ssh_port

                        if ('ssh_port' in host_list_class.host_ip_dic[host_ip].keys()):
                            if not tmp_ssh_port:
                                tmp_ssh_port = host_list_class.host_ip_dic[host_ip]['ssh_port']
                            else:
                                if tmp_ssh_port != host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                    # Make sure the ssh_port configuration is consistent.
                                    print_error('*Error*: ' + str(host_string) + ': ssh_port setting is conflict with the sign on "' + str(config.HOST_LIST) + '".')
                                    sys.exit(1)

                        specified_host_dic[host] = {}
                        specified_host_dic[host].setdefault('host_ip', [])
                        specified_host_dic[host].setdefault('ssh_port', [])
                        specified_host_dic[host]['host_ip'].append(host_ip)
                        specified_host_dic[host]['ssh_port'].append(tmp_ssh_port)
            elif is_ip(host):
                # If specify a unknown host_ip.
                specified_host_dic[host] = {}

                if ssh_port:
                    specified_host_dic[host]['ssh_port'] = ssh_port
            else:
                fuzzy_find_mark = False

                # With FUZZY_MATCH mode.
                # If specify a unknown-suspected incomplate host_ip/host_name.
                if config.FUZZY_MATCH:
                    # fuzzy matching host_ip.
                    for host_ip in host_list_class.host_ip_dic.keys():
                        if re.search(host, host_ip):
                            if not check_repetitiveness(host_ip, specified_host_dic):
                                print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_ip))

                                fuzzy_find_mark = True
                                tmp_ssh_port = ssh_port

                                if ('ssh_port' in host_list_class.host_ip_dic[host_ip].keys()):
                                    if not tmp_ssh_port:
                                        tmp_ssh_port = host_list_class.host_ip_dic[host_ip]['ssh_port']
                                    else:
                                        if tmp_ssh_port != host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                            # Make sure the ssh_port configuration is consistent.
                                            print_error('*Error*: ' + str(host_string) + ': ssh_port setting is conflict with the sign on "' + str(config.HOST_LIST) + '".')
                                            sys.exit(1)

                                specified_host_dic.setdefault(host, {})
                                specified_host_dic[host].setdefault('host_ip', [])
                                specified_host_dic[host].setdefault('ssh_port', [])
                                specified_host_dic[host]['host_ip'].append(host_ip)
                                specified_host_dic[host]['ssh_port'].append(tmp_ssh_port)

                    # fuzzy matching host_name.
                    for host_name in host_list_class.host_name_dic.keys():
                        if re.search(host, host_name):
                            for host_ip in host_list_class.host_name_dic[host_name]:
                                if not check_repetitiveness(host_ip, specified_host_dic):
                                    print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_name) + ' -> ' + str(host_ip))

                                    fuzzy_find_mark = True
                                    tmp_ssh_port = ssh_port

                                    if 'ssh_port' in host_list_class.host_ip_dic[host_ip].keys():
                                        if not tmp_ssh_port:
                                            tmp_ssh_port = host_list_class.host_ip_dic[host_ip]['ssh_port']
                                        else:
                                            if tmp_ssh_port != host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                                # Make sure the ssh_port configuration is consistent.
                                                print_error('*Error*: ' + str(host_string) + ': ssh_port setting is conflict with the sign on "' + str(config.HOST_LIST) + '".')
                                                sys.exit(1)

                                    specified_host_dic.setdefault(host, {})
                                    specified_host_dic[host].setdefault('host_ip', [])
                                    specified_host_dic[host].setdefault('ssh_port', [])
                                    specified_host_dic[host]['host_ip'].append(host_ip)
                                    specified_host_dic[host]['ssh_port'].append(tmp_ssh_port)

                if fuzzy_find_mark:
                    print('')
                else:
                    # If specify a unknown-suspected host_name.
                    specified_host_dic[host] = {}

                    if ssh_port:
                        specified_host_dic[host]['ssh_port'] = ssh_port

    return (specified_host_dic, excluded_host_list)
