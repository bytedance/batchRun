import os
import re
import sys
import copy
import pandas
import datetime
import subprocess

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config


def bprint(message, color='', background_color='', display_method='', date_format='', level='', indent=0, end='\n', save_file='', save_file_method='a'):
    """
    Enhancement of "print" function.

    color:            Specify font foreground color, default to follow the terminal settings.
    background_color: Specify font background color, default to follow the terminal settings.
    display_method:   Specify font display method, default to follow the terminal settings.
    date_format:      Will show date/time information before the message, such as "%Y_%m_%d %H:%M:%S". Default is "", means silent mode.
    level:            Will show message level information after date/time information, default is "", means show nothing.
    indent:           How much spaces to indent for specified message (with level information), default is 0, means no indentation.
    end:              Specify the character at the end of the output, default is "\n".
    save_file:        Save message into specified file, default is "", means save nothing.
    save_file_method: Save message with "append" or "write" mode, default is "append" mode.

    For "color" and "background_color":
    -----------------------------------------------
    字体色   |   背景色   |   Color    |   颜色描述
    -----------------------------------------------
    30       |   40       |   black    |   黑色
    31       |   41       |   red      |   红色
    32       |   42       |   green    |   绿色
    33       |   43       |   yellow   |   黃色
    34       |   44       |   blue     |   蓝色
    35       |   45       |   purple   |   紫色
    36       |   46       |   cyan     |   青色
    37       |   47       |   white    |   白色
    -----------------------------------------------

    For "display_method":
    ---------------------------
    显示方式   |   效果
    ---------------------------
    0          |   终端默认设置
    1          |   高亮显示
    4          |   使用下划线
    5          |   闪烁
    7          |   反白显示
    8          |   不可见
    ---------------------------

    For "level":
    -------------------------------------------------------------
    层级      |   说明
    -------------------------------------------------------------
    Debug     |   程序运行的详细信息, 主要用于调试.
    Info      |   程序运行过程信息, 主要用于将系统状态反馈给用户.
    Warning   |   表明会出现潜在错误, 但是一般不影响系统继续运行.
    Error     |   发生错误, 不确定系统是否可以继续运行.
    Fatal     |   发生严重错误, 程序会停止运行并退出.
    -------------------------------------------------------------

    For "save_file_method":
    -----------------------------------------------------------
    模式   |   说明
    -----------------------------------------------------------
    a      |   append mode, append content to existing file.
    w      |   write mode, create a new file and write content.
    -----------------------------------------------------------
    """
    # Check arguments.
    color_dic = {'black': 30,
                 'red': 31,
                 'green': 32,
                 'yellow': 33,
                 'blue': 34,
                 'purple': 35,
                 'cyan': 36,
                 'white': 37}

    if color:
        if (color not in color_dic.keys()) and (color not in color_dic.values()):
            bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): "' + str(color) + '": Invalid color setting, it must follow below rules.', date_format='', color=33, display_method=1)
            bprint('''
                    ----------------------------------
                    字体色   |   Color    |   颜色描述
                    ----------------------------------
                    30       |   black    |   黑色
                    31       |   red      |   红色
                    32       |   green    |   绿色
                    33       |   yellow   |   黃色
                    34       |   blue     |   蓝色
                    35       |   purple   |   紫色
                    36       |   cyan     |   青色
                    37       |   white    |   白色
                    ----------------------------------
            ''', date_format='', color=33, display_method=1)

            return

    background_color_dic = {'black': 40,
                            'red': 41,
                            'green': 42,
                            'yellow': 43,
                            'blue': 44,
                            'purple': 45,
                            'cyan': 46,
                            'white': 47}

    if background_color:
        if (background_color not in background_color_dic.keys()) and (background_color not in background_color_dic.values()):
            bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): "' + str(background_color) + '": Invalid background_color setting, it must follow below rules.', date_format='', color=33, display_method=1)
            bprint('''
                    ----------------------------------
                    背景色   |   Color    |   颜色描述
                    ----------------------------------
                    40       |   black    |   黑色
                    41       |   red      |   红色
                    42       |   green    |   绿色
                    43       |   yellow   |   黃色
                    44       |   blue     |   蓝色
                    45       |   purple   |   紫色
                    46       |   cyan     |   青色
                    47       |   white    |   白色
                    ----------------------------------
            ''', date_format='', color=33, display_method=1)

            return

    if display_method:
        valid_display_method_list = [0, 1, 4, 5, 7, 8]

        if display_method not in valid_display_method_list:
            bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): "' + str(display_method) + '": Invalid display_method setting, it must be integer between 0,1,4,5,7,8.', date_format='', color=33, display_method=1)
            bprint('''
                    ----------------------------
                    显示方式   |    效果
                    ----------------------------
                    0          |    终端默认设置
                    1          |    高亮显示
                    4          |    使用下划线
                    5          |    闪烁
                    7          |    反白显示
                    8          |    不可见
                    ----------------------------
            ''', date_format='', color=33, display_method=1)

            return

    if level:
        valid_level_list = ['Debug', 'Info', 'Warning', 'Error', 'Fatal']

        if level not in valid_level_list:
            bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): "' + str(level) + '": Invalid level setting, it must be Debug/Info/Warning/Error/Fatal.', date_format='', color=33, display_method=1)
            bprint('''
                    -------------------------------------------------------------
                    层级      |   说明
                    -------------------------------------------------------------
                    Debug     |   程序运行的详细信息, 主要用于调试.
                    Info      |   程序运行过程信息, 主要用于将系统状态反馈给用户.
                    Warning   |   表明会出现潜在错误, 但是一般不影响系统继续运行.
                    Error     |   发生错误, 不确定系统是否可以继续运行.
                    Fatal     |   发生严重错误, 程序会停止运行并退出.
                    -------------------------------------------------------------
            ''', date_format='', color=33, display_method=1)
            return

    if not re.match(r'^\d+$', str(indent)):
        bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
        bprint('                    ' + str(message), date_format='', color=33, display_method=1)
        bprint('*Warning* (bprint): "' + str(indent) + '": Invalid indent setting, it must be a positive integer, will reset to "0".', date_format='', color=33, display_method=1)

        indent = 0

    if save_file:
        valid_save_file_method_list = ['a', 'append', 'w', 'write']

        if save_file_method not in valid_save_file_method_list:
            bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): "' + str(save_file_method) + '": Invalid save_file_method setting, it must be "a" or "w".', date_format='', color=33, display_method=1)
            bprint('''
                    -----------------------------------------------------------
                    模式   |   说明
                    -----------------------------------------------------------
                    a      |   append mode, append content to existing file.
                    w      |   write mode, create a new file and write content.
                    -----------------------------------------------------------
            ''', date_format='', color=33, display_method=1)

            return

    # Set default color/background_color/display_method setting for different levels.
    if level:
        if level == 'Warning':
            if not display_method:
                display_method = 1

            if not color:
                color = 33
        elif level == 'Error':
            if not display_method:
                display_method = 1

            if not color:
                color = 31
        elif level == 'Fatal':
            if not display_method:
                display_method = 1

            if not background_color:
                background_color = 41

            if background_color == 41:
                if not color:
                    color = 37
            else:
                if not color:
                    color = 35

    # Get final color setting.
    final_color_setting = ''

    if color or background_color or display_method:
        final_color_setting = '\033['

        if display_method:
            final_color_setting = str(final_color_setting) + str(display_method)

        if color:
            if not re.match(r'^\d{2}$', str(color)):
                color = color_dic[color]

            if re.match(r'^.*\d$', final_color_setting):
                final_color_setting = str(final_color_setting) + ';' + str(color)
            else:
                final_color_setting = str(final_color_setting) + str(color)

        if background_color:
            if not re.match(r'^\d{2}$', str(background_color)):
                background_color = background_color_dic[background_color]

            if re.match(r'^.*\d$', final_color_setting):
                final_color_setting = str(final_color_setting) + ';' + str(background_color)
            else:
                final_color_setting = str(final_color_setting) + str(background_color)

        final_color_setting = str(final_color_setting) + 'm'

    # Get current_time if date_format is specified.
    current_time = ''

    if date_format:
        try:
            current_time = datetime.datetime.now().strftime(date_format)
        except Exception:
            bprint('*Warning* (bprint): Meet some setting problem with below message.', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): "' + str(date_format) + '": Invalid date_format setting, suggest to use the default setting.', date_format='', color=33, display_method=1)
            return

    # Print message with specified format.
    final_message = ''

    if current_time:
        final_message = str(final_message) + '[' + str(current_time) + '] '

    if indent > 0:
        final_message = str(final_message) + ' ' * indent

    if level:
        final_message = str(final_message) + '*' + str(level) + '*: '

    final_message = str(final_message) + str(message)

    if final_color_setting:
        final_message_with_color = final_color_setting + str(final_message) + '\033[0m'
    else:
        final_message_with_color = final_message

    print(final_message_with_color, end=end)

    # Save file.
    if save_file:
        try:
            with open(save_file, save_file_method) as SF:
                SF.write(str(final_message) + '\n')
        except Exception as warning:
            bprint('*Warning* (bprint): Meet some problem when saveing below message into file "' + str(save_file) + '".', date_format='', color=33, display_method=1)
            bprint('                    ' + str(message), date_format='', color=33, display_method=1)
            bprint('*Warning* (bprint): ' + str(warning), date_format='', color=33, display_method=1)
            return


def is_ip(input_string):
    """
    Judge the input string is ip or not.
    """
    if re.match(r'^(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])$', input_string):
        return True
    else:
        return False


def wildcard_to_regex(pattern):
    """
    Convert a shell-style wildcard pattern (only '*' is special) into a compiled
    anchored regex. All other regex metacharacters in the pattern are escaped,
    so a group/host name like 'qa(v2)' or an IP like '10.5.5.5' is matched
    literally except for '*'.
    """
    escaped = re.escape(pattern).replace(r'\*', '.*')
    return re.compile('^' + escaped + '$')


def get_login_user():
    """
    Get login user with os.getlogin().
    If crash, try to get login user with tty and last command.
    If last command also does not work, set current user as login user.
    """
    user = subprocess.run(['whoami'], capture_output=True, text=True).stdout.strip()
    login_user = subprocess.run(['who', 'am', 'i'], capture_output=True, text=True).stdout.strip()

    if login_user:
        login_user = re.sub(r' .*', '', login_user)
    else:
        login_user = user

    return login_user


def create_dir(dir_path, permission=0o1777):
    """
    Create dir with specified permission.
    """
    if not os.path.exists(dir_path):
        try:
            os.makedirs(dir_path)
            os.chmod(dir_path, permission)
        except Exception as error:
            bprint('Failed on creating directory "' + str(dir_path) + '", ' + str(error), level='Error')
            sys.exit(1)


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

    return SP.returncode, stdout, stderr


class ParseHostList():
    """
    Parse host_list file, get group/host_ip/host_name related information.
    """
    def __init__(self, host_list_file=''):
        if host_list_file and os.path.exists(host_list_file):
            self.host_list_file = host_list_file
        elif config.host_list and os.path.exists(config.host_list):
            self.host_list_file = config.host_list

        self.host_list_dic = {}
        self.expanded_host_list_dic = {}
        self.host_ip_dic = {}
        self.host_name_dic = {}

        self.check_host_list()
        self.parse_host_list()
        self.expand_host_list_dic()

    def check_host_list(self):
        """
        Make sure self.host_list_file is defined and the file exists.
        """
        if not self.host_list_file:
            bprint('Variable "host_list" is not defined on batchRun config file "config.py".', level='Error')
            sys.exit(1)
        else:
            if not os.path.exists(self.host_list_file):
                bprint('"' + str(self.host_list_file) + '": No such host list file.', level='Error')
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
        with open(self.host_list_file, 'r') as HF:
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
                            bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                            bprint('Group "' + str(group) + '" is defined repeatedly.', color='red', display_method=1, indent=9)
                            sys.exit(1)
                    else:
                        bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                        bprint('Empty group setting for below line.', color='red', display_method=1, indent=9)
                        bprint(line, color='red', display_method=1, indent=9)
                        sys.exit(1)
                elif re.match(r'^\s*([0-9\.]+)\s*((?:ssh_host=\S+|ssh_port=\d+)\s*){0,2}(#.*)?\s*$', line):
                    # Get host_ip/host_name/ssh_port setting.
                    # ssh_host and ssh_port may appear in either order.
                    my_match = re.match(r'^\s*([0-9\.]+)\b', line)
                    host_ip = my_match.group(1)
                    host_name_match = re.search(r'ssh_host=(\S+)', line)
                    ssh_port_match = re.search(r'ssh_port=(\d+)', line)
                    host_name = host_name_match.group(1) if host_name_match else None
                    ssh_port = ssh_port_match.group(1) if ssh_port_match else None

                    # Make sure it is a valid ip.
                    if not is_ip(host_ip):
                        bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                        bprint('"' + str(host_ip) + '": Invalid host ip.', color='red', display_method=1, indent=9)
                        sys.exit(1)

                    if not group:
                        # Must define group before host_ip.
                        bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                        bprint('Group information is missing for host "' + str(host_ip) + '".', color='red', display_method=1, indent=9)
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
                        bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                        bprint(line, color='red', display_method=1, indent=9)
                        sys.exit(1)

            # Switch unknown_lines into sub_groups on group setting.
            self.switch_unknown_lines()

            # Make sure self.host_list_dic is not empty.
            if not self.host_list_dic:
                bprint('No valid setting on "' + str(self.host_list_file) + '".', level='Error')
                sys.exit(1)

            # Make sure self.host_list_dic group is not empty.
            for group in self.host_list_dic.keys():
                if not self.host_list_dic[group]:
                    bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                    bprint('Group "' + str(group) + '" is empty on "' + str(self.host_list_file) + '".', color='red', display_method=1, indent=9)
                    sys.exit(1)

    def update_host_list_dic(self, group, host_ip, host_name, ssh_port):
        """
        Update self.host_list_dic[group]['hosts']
        """
        self.host_list_dic[group].setdefault('hosts', {})
        self.host_list_dic[group]['hosts'].setdefault(host_ip, {})

        # Update host_name.
        if host_name:
            if 'host_name' not in self.host_list_dic[group]['hosts'][host_ip]:
                self.host_list_dic[group]['hosts'][host_ip]['host_name'] = [host_name, ]
            else:
                if host_name not in self.host_list_dic[group]['hosts'][host_ip]['host_name']:
                    self.host_list_dic[group]['hosts'][host_ip]['host_name'].append(host_name)
                else:
                    bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                    bprint('host_ip "' + str(host_ip) + '" & host_name "' + str(host_name) + '" is defined repeatedly.', color='red', display_method=1, indent=9)
                    sys.exit(1)

        # Update ssh_port.
        if ssh_port:
            if 'ssh_port' not in self.host_list_dic[group]['hosts'][host_ip]:
                self.host_list_dic[group]['hosts'][host_ip]['ssh_port'] = ssh_port
            else:
                if self.host_list_dic[group]['hosts'][host_ip]['ssh_port'] != ssh_port:
                    bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                    bprint('Host "' + str(host_ip) + '" have different ssh port "' + str(self.host_list_dic[group]['hosts'][host_ip]['ssh_port']) + '" & "' + str(ssh_port) + '".', color='red', display_method=1, indent=9)
                    sys.exit(1)

    def update_host_ip_dic(self, group, host_ip, host_name, ssh_port):
        """
        Update self.host_ip_dic.
        """
        # Update groups.
        if host_ip not in self.host_ip_dic:
            self.host_ip_dic[host_ip] = {'groups': [group, ]}
        else:
            self.host_ip_dic[host_ip]['groups'].append(group)

        # Update host_name.
        if host_name:
            if 'host_name' not in self.host_ip_dic[host_ip]:
                self.host_ip_dic[host_ip]['host_name'] = [host_name, ]
            else:
                if host_name not in self.host_ip_dic[host_ip]['host_name']:
                    self.host_ip_dic[host_ip]['host_name'].append(host_name)

        # Update ssh_port.
        if ssh_port:
            if 'ssh_port' not in self.host_ip_dic[host_ip]:
                self.host_ip_dic[host_ip]['ssh_port'] = ssh_port
            else:
                if self.host_ip_dic[host_ip]['ssh_port'] != ssh_port:
                    bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                    bprint('Host "' + str(host_ip) + '" have different ssh port "' + str(self.host_ip_dic[host_ip]['ssh_port']) + '" & "' + str(ssh_port) + '".', color='red', display_method=1, indent=9)
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
            if 'unknown_lines' in self.host_list_dic[group]:
                for line in self.host_list_dic[group]['unknown_lines']:
                    if re.match(r'^\s*~\s*(\S+)\s*$', line):
                        # For excluded group/host_ip/host_name.
                        my_match = re.match(r'^\s*~\s*(\S+)\s*$', line)
                        exclude_item = my_match.group(1)

                        if exclude_item in self.host_list_dic:
                            # If match group.
                            self.host_list_dic[group].setdefault('exclude_groups', [])

                            if (exclude_item != group) and (exclude_item not in self.host_list_dic[group]['exclude_groups']):
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
                            find_mark = False

                            if re.search(r'\*', exclude_item):
                                exclude_item_re = wildcard_to_regex(exclude_item)

                                for known_group in self.host_list_dic.keys():
                                    if exclude_item_re.match(known_group):
                                        find_mark = True
                                        self.host_list_dic[group].setdefault('exclude_groups', [])

                                        if (known_group != group) and (known_group not in self.host_list_dic[group]['exclude_groups']):
                                            self.host_list_dic[group]['exclude_groups'].append(known_group)

                            if not find_mark:
                                bprint('Invalid setting on "' + str(self.host_list_file) + '", it could only exclude group/host_ip/host_name.', level='Error')
                                bprint(line, color='red', display_method=1, indent=9)
                                sys.exit(1)
                    else:
                        # For sub_group.
                        sub_group = line

                        if sub_group in self.host_list_dic:
                            self.host_list_dic[group].setdefault('sub_groups', [])

                            if sub_group not in self.host_list_dic[group]['sub_groups']:
                                self.host_list_dic[group]['sub_groups'].append(sub_group)
                            else:
                                bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                                bprint('Sub-group "' + str(sub_group) + '" is defined repeatedly on group "' + str(group) + '".', color='red', display_method=1, indent=9)
                                sys.exit(1)
                        else:
                            find_mark = False

                            if (line == 'all') or (line == 'ALL'):
                                find_mark = True
                                self.host_list_dic[group].setdefault('sub_groups', [])

                                for sub_group in self.host_list_dic.keys():
                                    if (sub_group != group) and (sub_group not in self.host_list_dic[group]['sub_groups']):
                                        self.host_list_dic[group]['sub_groups'].append(sub_group)
                            elif re.search(r'\*', sub_group):
                                sub_group_re = wildcard_to_regex(sub_group)

                                for known_group in self.host_list_dic.keys():
                                    if sub_group_re.match(known_group):
                                        find_mark = True
                                        self.host_list_dic[group].setdefault('sub_groups', [])

                                        if (known_group != group) and (known_group not in self.host_list_dic[group]['sub_groups']):
                                            self.host_list_dic[group]['sub_groups'].append(known_group)

                            if not find_mark:
                                bprint('Invalid setting on "' + str(self.host_list_file) + '".', level='Error')
                                bprint(line, color='red', display_method=1, indent=9)
                                sys.exit(1)

    def expand_host_list_dic(self):
        """
        Expand group setting on self.host_list_dic, get self.expanded_host_list_dic.
        """
        for group in self.host_list_dic.keys():
            group_hosts_dic = self.get_group_hosts_dic(group)
            self.expanded_host_list_dic[group] = group_hosts_dic

    def get_group_hosts_dic(self, group, ancestry=None):
        """
        Expand group setting to host_ip setting.

        ``ancestry`` is the chain of groups leading to ``group`` in the current
        recursion path. Any group reappearing in its own ancestry is a cycle.
        Using the full ancestry (not just the immediate parent) catches cycles of
        length >= 3 (A -> B -> C -> A) which the old parent-only check missed.
        """
        if ancestry is None:
            ancestry = []

        group_hosts_dic = {}

        if group in ancestry:
            chain = ' -> '.join(ancestry + [group])
            bprint('Group analysis forms a dead loop, ' + chain + '.', level='Error')
            sys.exit(1)

        if group in self.host_list_dic:
            # Save group "hosts" into group_hosts_dic.
            if 'hosts' in self.host_list_dic[group]:
                group_hosts_dic = copy.deepcopy(self.host_list_dic[group]['hosts'])

            # Save group "sub_groups" hosts into group_hosts_dic.
            if 'sub_groups' in self.host_list_dic[group]:
                for sub_group in self.host_list_dic[group]['sub_groups']:
                    if ('exclude_groups' in self.host_list_dic[group]) and (sub_group in self.host_list_dic[group]['exclude_groups']):
                        continue

                    if sub_group in ancestry or sub_group == group:
                        chain = ' -> '.join(ancestry + [group, sub_group])
                        bprint('Group analysis forms a dead loop, ' + chain + '.', level='Error')
                        sys.exit(1)

                    sub_group_hosts_dic = self.get_group_hosts_dic(sub_group, ancestry=ancestry + [group])

                    for host_ip in sub_group_hosts_dic.keys():
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
                    if exclude_group in ancestry or exclude_group == group:
                        chain = ' -> '.join(ancestry + [group, exclude_group])
                        bprint('Group analysis forms a dead loop, ' + chain + '.', level='Error')
                        sys.exit(1)

                    exclude_group_hosts_dic = self.get_group_hosts_dic(exclude_group, ancestry=ancestry + [group])

                    for host_ip in exclude_group_hosts_dic.keys():
                        if host_ip in group_hosts_dic:
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

    if host_name in host_list_class.host_name_dic:
        host_ip_list = host_list_class.host_name_dic[host_name]

    return host_ip_list


def check_repetitiveness(host, specified_host_dic):
    """
    If host in specified_host_dic, return True, else return False.
    """
    if specified_host_dic:
        if host in specified_host_dic:
            return True
        else:
            for specified_host in specified_host_dic.keys():
                if 'host_ip' in specified_host_dic[specified_host]:
                    if host in specified_host_dic[specified_host]['host_ip']:
                        return True
                elif 'host_name' in specified_host_dic[specified_host]:
                    if host in specified_host_dic[specified_host]['host_name']:
                        return True

    return False


def parse_specified_groups(specified_group_list, host_list_class=None, specified_host_dic=None, excluded_host_list=None, expected_group_list=None, excluded_group_list=None):
    """
    Specified group could be:
    group
    ~group

    Get specified_host_dic/excluded_host_list/expected_group_list/excluded_group_list from specified group(s).
    * specified_host_dic  : specified host information. (Will remove excluded host)
      specified_host_dic = {<host>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}
    * excluded_host_list  : excluded host(s).
    * expected_group_list : specified group(s). (Will remove excluded host)
    * excluded_group_list : excluded group(s).
    """
    if specified_host_dic is None:
        specified_host_dic = {}

    if excluded_host_list is None:
        excluded_host_list = []

    if expected_group_list is None:
        expected_group_list = []

    if excluded_group_list is None:
        excluded_group_list = []

    if not host_list_class:
        host_list_class = ParseHostList()

    # Expand "all/ALL" group on specified_group_list.
    if ('all' in specified_group_list) or ('ALL' in specified_group_list):
        if 'all' in specified_group_list:
            specified_group_list.remove('all')

        if 'ALL' in specified_group_list:
            specified_group_list.remove('ALL')

        specified_group_list.extend(list(host_list_class.host_list_dic.keys()))

    # Get expected and excluded group list.
    for group in specified_group_list:
        if re.match(r'^~(\S+)$', group):
            my_match = re.match(r'^~(\S+)$', group)
            excluded_group = my_match.group(1)

            if excluded_group in host_list_class.expanded_host_list_dic:
                excluded_group_list.append(excluded_group)
            else:
                find_mark = False

                if re.search(r'\*', excluded_group):
                    excluded_group_re = wildcard_to_regex(excluded_group)

                    for known_group in host_list_class.host_list_dic.keys():
                        if excluded_group_re.match(known_group):
                            find_mark = True
                            excluded_group_list.append(known_group)

                if not find_mark:
                    bprint('Invalid setting on host_list file.', level='Error')
                    bprint(str(group) + ': Invalid host group.', color='red', display_method=1, indent=9)
                    sys.exit(1)
        else:
            if group in host_list_class.expanded_host_list_dic:
                expected_group_list.append(group)
            else:
                find_mark = False

                if re.search(r'\*', group):
                    group_re = wildcard_to_regex(group)

                    for known_group in host_list_class.host_list_dic.keys():
                        if group_re.match(known_group):
                            find_mark = True
                            expected_group_list.append(known_group)

                if not find_mark:
                    bprint(str(group) + ': Invalid host group.', level='Error')
                    sys.exit(1)

    # Remove excluded group(s) from expected_group_list.
    copy_expected_group_list = copy.deepcopy(expected_group_list)

    for group in copy_expected_group_list:
        if group in excluded_group_list:
            expected_group_list.remove(group)

    # Get excluded_host_list.
    for group in excluded_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            if host_ip not in excluded_host_list:
                excluded_host_list.append(host_ip)

    # Get specified_host_dic.
    for group in expected_group_list:
        for host_ip in host_list_class.expanded_host_list_dic[group].keys():
            # Remove excluded host(s).
            if host_ip in excluded_host_list:
                continue
            elif 'host_name' in host_list_class.host_ip_dic[host_ip]:
                # Skip this host_ip entirely if any of its host_names is excluded.
                # (The previous "continue" only broke the inner loop, leaving the host included.)
                if any(host_name in excluded_host_list for host_name in host_list_class.host_ip_dic[host_ip]['host_name']):
                    continue

            if not check_repetitiveness(host_ip, specified_host_dic):
                specified_host_dic[host_ip] = {}

                if host_ip in host_list_class.host_ip_dic:
                    if 'host_name' in host_list_class.host_ip_dic[host_ip]:
                        specified_host_dic[host_ip]['host_name'] = host_list_class.host_ip_dic[host_ip]['host_name']

                    if 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                        specified_host_dic[host_ip]['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']

                    if 'groups' in host_list_class.host_ip_dic[host_ip]:
                        specified_host_dic[host_ip]['groups'] = host_list_class.host_ip_dic[host_ip]['groups']

    # Update expected_group_list.
    for host in specified_host_dic:
        if 'groups' in specified_host_dic[host]:
            for host_group in specified_host_dic[host]['groups']:
                if host_group not in expected_group_list:
                    expected_group_list.append(host_group)

    return specified_host_dic, excluded_host_list, expected_group_list, excluded_group_list


def parse_specified_hosts(specified_host_list, host_list_class=None, specified_host_dic=None, excluded_host_list=None, expected_group_list=None, excluded_group_list=None):
    """
    Specified host could be:
    host_ip
    host_name
    host_ip:ssh_port
    host_name:ssh_port
    ~host_ip
    ~host_name

    Get expected hosts and excluded hosts from specified host(s).
    * specified_host_dic  : specified host information. (Will remove excluded host)
      specified_host_dic = {<host>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}
      or
      specified_host_dic = {<host>: {'host_ip': [<host_ip>,], 'ssh_port': [<ssh_port>,], 'groups': [[<group>,],]}}
      or
      specified_host_dic = {<host>: {'ssh_port': <ssh_port>}}
    * excluded_host_list  : excluded host(s).
    * excluded_host_list  : excluded host(s).
    """
    if specified_host_dic is None:
        specified_host_dic = {}

    if excluded_host_list is None:
        excluded_host_list = []

    if expected_group_list is None:
        expected_group_list = []

    if excluded_group_list is None:
        excluded_group_list = []

    if not host_list_class:
        host_list_class = ParseHostList()

    # Expand "all/ALL" host on specified_host_list.
    if ('all' in specified_host_list) or ('ALL' in specified_host_list):
        if 'all' in specified_host_list:
            specified_host_list.remove('all')

        if 'ALL' in specified_host_list:
            specified_host_list.remove('ALL')

        specified_host_list.extend(list(host_list_class.host_ip_dic.keys()))

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
            bprint(str(host_string) + ': Invalid host format.', level='Error')
            sys.exit(1)

        if host and (not check_repetitiveness(host, specified_host_dic)):
            if host in host_list_class.host_ip_dic:
                # If specify a known host_ip.
                # specified_host_dic = {<host>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}
                specified_host_dic[host] = {}

                if 'host_name' in host_list_class.host_ip_dic[host]:
                    specified_host_dic[host]['host_name'] = host_list_class.host_ip_dic[host]['host_name']

                if 'ssh_port' in host_list_class.host_ip_dic[host]:
                    if not ssh_port:
                        specified_host_dic[host]['ssh_port'] = host_list_class.host_ip_dic[host]['ssh_port']
                    else:
                        if ssh_port == host_list_class.host_ip_dic[host]['ssh_port']:
                            specified_host_dic[host]['ssh_port'] = host_list_class.host_ip_dic[host]['ssh_port']
                        else:
                            bprint(str(host_string) + ': ssh_port setting is conflict with the sign on host_list file.', level='Error')
                            sys.exit(1)
                else:
                    if ssh_port:
                        specified_host_dic[host]['ssh_port'] = ssh_port

                if 'groups' in host_list_class.host_ip_dic[host]:
                    specified_host_dic[host]['groups'] = host_list_class.host_ip_dic[host]['groups']
            elif host in host_list_class.host_name_dic:
                # If specify a known host_name.
                # specified_host_dic = {<host>: {'host_ip': [<host_ip>,], 'ssh_port': [<ssh_port>,], 'groups': [[<group>,],]}}
                specified_host_dic.setdefault(host, {'host_ip': [], 'ssh_port': [], 'groups': []})

                for host_ip in host_list_class.host_name_dic[host]:
                    if not check_repetitiveness(host_ip, specified_host_dic):
                        specified_host_dic[host]['host_ip'].append(host_ip)

                        if 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                            if not ssh_port:
                                specified_host_dic[host]['ssh_port'].append(host_list_class.host_ip_dic[host_ip]['ssh_port'])
                            else:
                                if ssh_port == host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                    specified_host_dic[host]['ssh_port'].append(host_list_class.host_ip_dic[host_ip]['ssh_port'])
                                else:
                                    bprint(str(host_string) + ': ssh_port setting is conflict with the sign on host_list file.', level='Error')
                                    sys.exit(1)
                        else:
                            specified_host_dic[host]['ssh_port'].append(ssh_port)

                        if 'groups' in host_list_class.host_ip_dic[host_ip]:
                            specified_host_dic[host]['groups'].append(host_list_class.host_ip_dic[host_ip]['groups'])
            elif is_ip(host):
                # If specify a unknown host_ip.
                # specified_host_dic = {<host>: {'ssh_port': <ssh_port>}}
                specified_host_dic[host] = {}

                if ssh_port:
                    specified_host_dic[host]['ssh_port'] = ssh_port
            else:
                fuzzy_find_mark = False

                if re.search(r'\*', host):
                    host_re = wildcard_to_regex(host)

                    # fuzzy matching host_ip.
                    # specified_host_dic = {<host_ip>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}
                    for host_ip in host_list_class.host_ip_dic.keys():
                        if host_re.match(host_ip):
                            if not check_repetitiveness(host_ip, specified_host_dic):
                                print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_ip))
                                fuzzy_find_mark = True
                                specified_host_dic[host_ip] = {}

                                if 'host_name' in host_list_class.host_ip_dic[host_ip]:
                                    specified_host_dic[host_ip]['host_name'] = host_list_class.host_ip_dic[host_ip]['host_name']

                                if 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                                    if not ssh_port:
                                        specified_host_dic[host_ip]['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']
                                    else:
                                        if ssh_port == host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                            specified_host_dic[host_ip]['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']
                                        else:
                                            bprint(str(host_string) + ': ssh_port setting is conflict with the sign on host_list file.', level='Error')
                                            sys.exit(1)
                                else:
                                    if ssh_port:
                                        specified_host_dic[host_ip]['ssh_port'] = ssh_port

                                if 'groups' in host_list_class.host_ip_dic[host_ip]:
                                    specified_host_dic[host_ip]['groups'] = host_list_class.host_ip_dic[host_ip]['groups']

                    # fuzzy matching host_name.
                    # specified_host_dic = {<host_ip>: {'host_name': [<host_name>,], 'ssh_port': <ssh_port>, 'groups': [<group>,]}}
                    for host_name in host_list_class.host_name_dic.keys():
                        if host_re.match(host_name):
                            for host_ip in host_list_class.host_name_dic[host_name]:
                                if not check_repetitiveness(host_ip, specified_host_dic):
                                    print('[FUZZY MATCH] ' + str(host) + ' -> ' + str(host_name) + ' -> ' + str(host_ip))
                                    fuzzy_find_mark = True
                                    specified_host_dic[host_ip] = {}

                                    if 'host_name' in host_list_class.host_ip_dic[host_ip]:
                                        specified_host_dic[host_ip]['host_name'] = host_list_class.host_ip_dic[host_ip]['host_name']

                                    if 'ssh_port' in host_list_class.host_ip_dic[host_ip]:
                                        if not ssh_port:
                                            specified_host_dic[host_ip]['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']
                                        else:
                                            if ssh_port == host_list_class.host_ip_dic[host_ip]['ssh_port']:
                                                specified_host_dic[host_ip]['ssh_port'] = host_list_class.host_ip_dic[host_ip]['ssh_port']
                                            else:
                                                bprint(str(host_string) + ': ssh_port setting is conflict with the sign on host_list file.', level='Error')
                                                sys.exit(1)
                                    else:
                                        if ssh_port:
                                            specified_host_dic[host_ip]['ssh_port'] = ssh_port

                                    if 'groups' in host_list_class.host_ip_dic[host_ip]:
                                        specified_host_dic[host_ip]['groups'] = host_list_class.host_ip_dic[host_ip]['groups']

                if fuzzy_find_mark:
                    print('')
                else:
                    # If specify a unknown-suspected host_name.
                    # specified_host_dic = {<host>: {'ssh_port': <ssh_port>}}
                    specified_host_dic[host] = {}

                    if ssh_port:
                        specified_host_dic[host]['ssh_port'] = ssh_port

    # Remove excluded host(s) from specified_host_dic.
    copy_specified_host_dic = copy.deepcopy(specified_host_dic)

    for specified_host in copy_specified_host_dic:
        if specified_host in excluded_host_list:
            specified_host_dic.pop(specified_host)
        else:
            # Switch host_name to host_ip, and swich host_ip to host_name, judge again.
            switch_host_list = []

            if is_ip(specified_host):
                if specified_host in host_list_class.host_ip_dic:
                    if 'host_name' in host_list_class.host_ip_dic[specified_host]:
                        switch_host_list = host_list_class.host_ip_dic[specified_host]['host_name']
            else:
                if specified_host in host_list_class.host_name_dic:
                    switch_host_list = host_list_class.host_name_dic[specified_host]

            for switch_host in switch_host_list:
                if switch_host in excluded_host_list:
                    specified_host_dic.pop(specified_host)
                    break

    # Update expected_group_list.
    for host in specified_host_dic:
        if 'groups' in specified_host_dic[host]:
            for host_group in specified_host_dic[host]['groups']:
                if host_group not in expected_group_list:
                    expected_group_list.append(host_group)

    return specified_host_dic, excluded_host_list, expected_group_list, excluded_group_list


def write_csv(csv_file, content_dic):
    """
    Write csv with content_dic.
    content_dic = {
        'title_1': [column1_1, columne1_2, ...],
        'title_2': [column2_1, columne2_2, ...],
        ...
    }
    """
    df = pandas.DataFrame(content_dic)
    df.to_csv(csv_file, index=False)


def read_csv(csv_file):
    """
    Read csv and return a dict (orient='list': {title: [v1, v2, ...]}),
    matching the input format expected by write_csv.
    """
    df = pandas.read_csv(csv_file)
    return df.to_dict(orient='list')


# ----------------------------------------------------------------------
# Safe expression evaluator (replaces eval() on user-supplied select strings)
# ----------------------------------------------------------------------
import ast as _ast
import operator as _operator

_SAFE_BINOPS = {
    _ast.Add: _operator.add, _ast.Sub: _operator.sub, _ast.Mult: _operator.mul,
    _ast.Div: _operator.truediv, _ast.FloorDiv: _operator.floordiv, _ast.Mod: _operator.mod,
    _ast.Pow: _operator.pow,
}
_SAFE_CMPOPS = {
    _ast.Eq: _operator.eq, _ast.NotEq: _operator.ne, _ast.Lt: _operator.lt,
    _ast.LtE: _operator.le, _ast.Gt: _operator.gt, _ast.GtE: _operator.ge,
    _ast.In: lambda a, b: a in b, _ast.NotIn: lambda a, b: a not in b,
}
_SAFE_UNARY = {_ast.UAdd: _operator.pos, _ast.USub: _operator.neg, _ast.Not: _operator.not_}

# Whitelisted built-in functions (callable only by direct name, no attribute access).
_SAFE_FUNCS = {
    'len': len, 'int': int, 'float': float, 'str': str, 'bool': bool,
    'abs': abs, 'min': min, 'max': max, 'round': round,
    'upper': lambda x: x.upper() if isinstance(x, str) else str(x).upper(),
    'lower': lambda x: x.lower() if isinstance(x, str) else str(x).lower(),
}


class SafeEvalError(Exception):
    pass


class _SafeEvalVisitor(_ast.NodeVisitor):
    """
    Evaluate a restricted Python expression. Names are resolved against the
    provided mapping. Disallows attribute access, subscript, calls, imports,
    comprehensions and any name beginning with an underscore (blocks
    __builtins__/dunder escapes).
    """

    def __init__(self, names):
        self.names = names

    def visit_Expression(self, node):
        return self.visit(node.body)

    def visit_Constant(self, node):
        return node.value

    def visit_Name(self, node):
        if not isinstance(node.ctx, _ast.Load):
            raise SafeEvalError('disallowed name context')

        name = node.id

        if name.startswith('_'):
            raise SafeEvalError('access to "%s" is not allowed' % name)

        if name not in self.names:
            raise SafeEvalError('unknown name "%s"' % name)

        return self.names[name]

    def visit_BoolOp(self, node):
        values = [self.visit(v) for v in node.values]

        if isinstance(node.op, _ast.And):
            result = True

            for v in values:
                result = result and v

            return result
        else:
            result = False

            for v in values:
                result = result or v

            return result

    def visit_UnaryOp(self, node):
        op = _SAFE_UNARY.get(type(node.op))

        if op is None:
            raise SafeEvalError('disallowed unary op')

        return op(self.visit(node.operand))

    def visit_BinOp(self, node):
        op = _SAFE_BINOPS.get(type(node.op))

        if op is None:
            raise SafeEvalError('disallowed binary op')

        return op(self.visit(node.left), self.visit(node.right))

    def visit_Compare(self, node):
        left = self.visit(node.left)
        result = True

        for op, comparator in zip(node.ops, node.comparators):
            cmp = _SAFE_CMPOPS.get(type(op))

            if cmp is None:
                raise SafeEvalError('disallowed comparison op')

            right = self.visit(comparator)
            result = result and cmp(left, right)
            left = right

        return result

    def visit_List(self, node):
        return [self.visit(e) for e in node.elts]

    def visit_Tuple(self, node):
        return tuple(self.visit(e) for e in node.elts)

    def visit_Set(self, node):
        return set(self.visit(e) for e in node.elts)

    def visit_Call(self, node):
        # Only direct calls to whitelisted function names: func(...) where func is a Name.
        # Disallows calling attributes (x.method()), results of calls (f()(x)), etc.
        if not isinstance(node.func, _ast.Name):
            raise SafeEvalError('only direct function calls are allowed')

        func_name = node.func.id

        if func_name not in _SAFE_FUNCS:
            raise SafeEvalError('function "%s" is not allowed' % func_name)

        if node.keywords:
            raise SafeEvalError('keyword arguments are not allowed')

        args = [self.visit(a) for a in node.args]

        try:
            return _SAFE_FUNCS[func_name](*args)
        except Exception as e:
            raise SafeEvalError('function "%s" failed: %s' % (func_name, e))

    def visit_Subscript(self, node):
        # Allow indexing and slicing on str/list/tuple/dict values, not on names directly.
        value = self.visit(node.value)

        if isinstance(node.slice, _ast.Slice):
            lower = self.visit(node.slice.lower) if node.slice.lower is not None else None
            upper = self.visit(node.slice.upper) if node.slice.upper is not None else None
            step = self.visit(node.slice.step) if node.slice.step is not None else None
            return value[lower:upper:step]

        index = self.visit(node.slice)
        return value[index]

    def generic_visit(self, node):
        raise SafeEvalError('disallowed expression element: %s' % type(node).__name__)


def safe_eval_expr(expression, names):
    """
    Safely evaluate a boolean/arithmetic expression against the ``names`` dict.

    Returns the evaluated value. Raises SafeEvalError on any disallowed construct.
    Example: safe_eval_expr('load > 4 and cpu_thread < 16', {'load': 8, 'cpu_thread': 8}) -> True
    """
    if not isinstance(expression, str) or not expression.strip():
        raise SafeEvalError('empty expression')

    tree = _ast.parse(expression, mode='eval')
    return _SafeEvalVisitor(names).visit(tree)
