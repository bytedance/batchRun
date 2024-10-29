# -*- coding: utf-8 -*-
################################
# File Name   : batch_run_gui.py
# Author      : liyanqing.1987
# Created On  : 2024-10-14 09:57:06
# Description :
################################
import os
import re
import sys
import copy
import json
import getpass
import datetime
import qdarkstyle

from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QAction, qApp, QTabWidget, QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QMessageBox, QLineEdit, QHeaderView, QFileDialog, QTextEdit, QTreeWidget, QTreeWidgetItem, QDateEdit, QSplitter
from PyQt5.QtGui import QIcon, QBrush, QColor
from PyQt5.QtCore import Qt, QThread, QProcess, QDate

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common
import common_lsf
import common_pyqt5

os.environ['PYTHONUNBUFFERED'] = '1'
CURRENT_USER = getpass.getuser()
VERSION = 'V2.0'
VERSION_DATE = '2024.10.28'


# Solve some unexpected warning message.
if 'XDG_RUNTIME_DIR' not in os.environ:
    user = getpass.getuser()
    os.environ['XDG_RUNTIME_DIR'] = '/tmp/runtime-' + str(user)

    if not os.path.exists(os.environ['XDG_RUNTIME_DIR']):
        os.makedirs(os.environ['XDG_RUNTIME_DIR'])
        os.chmod(os.environ['XDG_RUNTIME_DIR'], 0o777)


class MainWindow(QMainWindow):
    """
    Main window of batchRun.
    """
    def __init__(self):
        super().__init__()

        # Init variables.
        self.init_var()

        # Generate GUI.
        self.init_ui()

        # Switch to "HOST" tab by default.
        self.main_tab.setCurrentWidget(self.host_tab)

    def init_var(self):
        """
        Set necessary variable.
        """
        # self.host_queue_dic: get host<->queue relationship.
        common.bprint('Getting LSF host-queue relationship, please wait a moment ...', date_format='%Y-%m-%d %H:%M:%S')
        my_show_message = ShowMessage('Info', 'Getting LSF host-queue relationship, please wait a moment ...')
        my_show_message.start()
        self.host_queue_dic = common_lsf.get_host_queue_info()
        my_show_message.terminate()

        # self.host_list_class: get host-group information from host.list.
        self.host_list_class = common.ParseHostList()

        # self.completer_host_list: completer for Host.
        # self.host_group_relationship_dic: host -> group relationship.
        self.completer_host_list = []
        self.host_group_relationship_dic = {}

        for group in self.host_list_class.expanded_host_list_dic.keys():
            for host_ip in self.host_list_class.expanded_host_list_dic[group].keys():
                if host_ip not in self.completer_host_list:
                    self.completer_host_list.append(host_ip)

                for host_name in self.host_list_class.expanded_host_list_dic[group][host_ip]['host_name']:
                    if host_name not in self.completer_host_list:
                        self.completer_host_list.append(host_name)

                if host_ip not in self.host_group_relationship_dic:
                    self.host_group_relationship_dic[host_ip] = [group]
                else:
                    if group not in self.host_group_relationship_dic[host_ip]:
                        self.host_group_relationship_dic[host_ip].append(group)

        # self.run_tab_host_dic: get selected host_ip(s)/host_name(s) from GROUP or HOST tab.
        self.run_tab_host_dic = {}

        for group in self.host_list_class.expanded_host_list_dic.keys():
            for host_ip in self.host_list_class.expanded_host_list_dic[group].keys():
                host_name = ' '.join(self.host_list_class.expanded_host_list_dic[group][host_ip]['host_name'])
                self.run_tab_host_dic[host_ip] = {'host_name': host_name, 'state': Qt.Checked, 'output_message': ''}

    def init_ui(self):
        """
        Main process, draw the main graphic frame.
        """
        # Add menubar.
        self.gen_menubar()

        # Define main Tab widget
        self.main_tab = QTabWidget(self)
        self.setCentralWidget(self.main_tab)

        # Define sub-tabs
        self.group_tab = QWidget()
        self.host_tab = QWidget()
        self.run_tab = QWidget()
        self.log_tab = QWidget()

        # Add the sub-tabs into main Tab widget
        self.main_tab.addTab(self.group_tab, 'GROUP')
        self.main_tab.addTab(self.host_tab, 'HOST')
        self.main_tab.addTab(self.run_tab, 'RUN')
        self.main_tab.addTab(self.log_tab, 'LOG')

        # Generate the sub-tabs
        self.gen_group_tab()
        self.gen_host_tab()
        self.gen_run_tab()
        self.gen_log_tab()

        # Show main window
        common_pyqt5.auto_resize(self)
        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
        self.setWindowTitle('batchRun ' + str(VERSION))
        self.setWindowIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/monitor.ico'))
        common_pyqt5.center_window(self)

    def gen_menubar(self):
        """
        Generate menubar.
        """
        menubar = self.menuBar()

        # File
        export_group_table_action = QAction('Export group table', self)
        export_group_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_group_table_action.triggered.connect(self.export_group_table)

        export_host_table_action = QAction('Export host table', self)
        export_host_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_host_table_action.triggered.connect(self.export_host_table)

        export_run_table_action = QAction('Export run table', self)
        export_run_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_run_table_action.triggered.connect(self.export_run_table)

        export_log_table_action = QAction('Export log table', self)
        export_log_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_log_table_action.triggered.connect(self.export_log_table)

        exit_action = QAction('Exit', self)
        exit_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/exit.png'))
        exit_action.triggered.connect(qApp.quit)

        file_menu = menubar.addMenu('File')
        file_menu.addAction(export_group_table_action)
        file_menu.addAction(export_host_table_action)
        file_menu.addAction(export_run_table_action)
        file_menu.addAction(export_log_table_action)
        file_menu.addAction(exit_action)

        # Help
        version_action = QAction('Version', self)
        version_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/version.png'))
        version_action.triggered.connect(self.show_version)

        about_action = QAction('About', self)
        about_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/about.png'))
        about_action.triggered.connect(self.show_about)

        help_menu = menubar.addMenu('Help')
        help_menu.addAction(version_action)
        help_menu.addAction(about_action)

    def show_version(self):
        """
        Show batchRun version information.
        """
        QMessageBox.about(self, 'batchRun', 'Version: ' + str(VERSION) + ' (' + str(VERSION_DATE) + ')')

    def show_about(self):
        """
        Show batchRun about information.
        """
        about_message = """
Thanks for downloading batchRun.

batchRun is a batch opration, asset management, and information collection tool applied to HPC systems.

Please be free to contact liyanqing1987@163.com if any question."""

        QMessageBox.about(self, 'batchRun About', about_message)

# For group TAB (begin) #
    def gen_group_tab(self):
        """
        Generate the GROUP tab on batchRun GUI, show host.list informations.
        """
        # self.group_tab
        self.group_tab_qtree = QTreeWidget(self.group_tab)

        self.group_tab_frame0 = QFrame(self.group_tab)
        self.group_tab_frame0.setFrameShadow(QFrame.Raised)
        self.group_tab_frame0.setFrameShape(QFrame.Box)

        self.group_tab_table = QTableWidget(self.group_tab)

        # self.group_tab - Grid
        group_tab_grid = QGridLayout()

        group_tab_grid.addWidget(self.group_tab_qtree, 0, 0, 2, 1)
        group_tab_grid.addWidget(self.group_tab_frame0, 0, 1)
        group_tab_grid.addWidget(self.group_tab_table, 1, 1)

        group_tab_grid.setRowStretch(0, 1)
        group_tab_grid.setRowStretch(1, 20)

        group_tab_grid.setColumnStretch(0, 1)
        group_tab_grid.setColumnStretch(1, 4)

        self.group_tab.setLayout(group_tab_grid)

        # Generate sub-frames
        self.gen_group_tab_qtree()
        self.gen_group_tab_frame0()
        self.gen_group_tab_table()

    def gen_group_tab_qtree(self):
        # self.group_tab_qtree
        self.group_tab_qtree.setColumnCount(1)
        self.group_tab_qtree.setHeaderLabels(['     Group  -  Sub_Group / Sub_Host', ])
        self.group_tab_qtree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.group_tab_qtree.header().setStretchLastSection(False)

        for group in self.host_list_class.host_list_dic.keys():
            group_item = QTreeWidgetItem(self.group_tab_qtree)
            group_item.setText(0, group)
            group_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/g.png'))

            if ('sub_groups' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['sub_groups']:
                for sub_group in self.host_list_class.host_list_dic[group]['sub_groups']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, sub_group)
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/g.png'))
                    group_item.addChild(child_item)

            if ('exclude_groups' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['exclude_groups']:
                for exclude_group in self.host_list_class.host_list_dic[group]['exclude_groups']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, '~' + str(exclude_group))
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/g.png'))
                    group_item.addChild(child_item)

            if ('hosts' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['hosts']:
                for host in self.host_list_class.host_list_dic[group]['hosts']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, host)
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/h.png'))
                    group_item.addChild(child_item)

            if ('exclude_hosts' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['exclude_hosts']:
                for exclude_host in self.host_list_class.host_list_dic[group]['exclude_hosts']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, '~' + str(exclude_host))
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/h.png'))
                    group_item.addChild(child_item)

    def gen_group_tab_frame0(self):
        # self.group_tab_frame0
        # "Group" item.
        group_tab_group_label = QLabel('Group', self.group_tab_frame0)
        group_tab_group_label.setStyleSheet("font-weight: bold;")
        group_tab_group_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.group_tab_group_combo = common_pyqt5.QComboCheckBox(self.group_tab_frame0)
        self.set_group_tab_group_combo()

        # "Queue" item.
        group_tab_queue_label = QLabel('Queue', self.group_tab_frame0)
        group_tab_queue_label.setStyleSheet("font-weight: bold;")
        group_tab_queue_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.group_tab_queue_combo = common_pyqt5.QComboCheckBox(self.group_tab_frame0)
        self.set_group_tab_queue_combo()

        # "Host" item.
        group_tab_host_label = QLabel('Host', self.group_tab_frame0)
        group_tab_host_label.setStyleSheet("font-weight: bold;")
        group_tab_host_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.group_tab_host_line = QLineEdit()
        self.group_tab_host_line.returnPressed.connect(self.gen_group_tab_table)

        group_tab_host_line_completer = common_pyqt5.get_completer(self.completer_host_list)
        self.group_tab_host_line.setCompleter(group_tab_host_line_completer)

        # empty item.
        group_tab_empty_label = QLabel('', self.group_tab_frame0)

        # "Check" button.
        group_tab_check_button = QPushButton('Check', self.group_tab_frame0)
        group_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        group_tab_check_button.clicked.connect(self.gen_group_tab_table)

        # "toRun" button.
        group_tab_torun_button = QPushButton('toRun', self.group_tab_frame0)
        group_tab_torun_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        group_tab_torun_button.clicked.connect(self.group_to_run_tab)

        # self.group_tab_frame0 - Grid
        group_tab_frame0_grid = QGridLayout()

        group_tab_frame0_grid.addWidget(group_tab_group_label, 0, 0)
        group_tab_frame0_grid.addWidget(self.group_tab_group_combo, 0, 1)
        group_tab_frame0_grid.addWidget(group_tab_queue_label, 0, 2)
        group_tab_frame0_grid.addWidget(self.group_tab_queue_combo, 0, 3)
        group_tab_frame0_grid.addWidget(group_tab_host_label, 0, 4)
        group_tab_frame0_grid.addWidget(self.group_tab_host_line, 0, 5)
        group_tab_frame0_grid.addWidget(group_tab_empty_label, 0, 6)
        group_tab_frame0_grid.addWidget(group_tab_check_button, 0, 7)
        group_tab_frame0_grid.addWidget(group_tab_torun_button, 0, 8)

        group_tab_frame0_grid.setColumnStretch(0, 1)
        group_tab_frame0_grid.setColumnStretch(1, 1)
        group_tab_frame0_grid.setColumnStretch(2, 1)
        group_tab_frame0_grid.setColumnStretch(3, 1)
        group_tab_frame0_grid.setColumnStretch(4, 1)
        group_tab_frame0_grid.setColumnStretch(5, 1)
        group_tab_frame0_grid.setColumnStretch(6, 1)
        group_tab_frame0_grid.setColumnStretch(7, 1)
        group_tab_frame0_grid.setColumnStretch(8, 1)

        self.group_tab_frame0.setLayout(group_tab_frame0_grid)

    def set_group_tab_group_combo(self, checked_group_list=['ALL',]):
        """
        Set (initialize) self.group_tab_group_combo.
        """
        self.group_tab_group_combo.clear()

        group_list = copy.deepcopy(list(self.host_list_class.expanded_host_list_dic.keys()))
        group_list.sort()
        group_list.insert(0, 'ALL')

        for group in group_list:
            self.group_tab_group_combo.addCheckBoxItem(group)

        # Set to checked status for checked_queue_list.
        for (i, qBox) in enumerate(self.group_tab_group_combo.checkBoxList):
            if (qBox.text() in checked_group_list) and (qBox.isChecked() is False):
                self.group_tab_group_combo.checkBoxList[i].setChecked(True)

    def set_group_tab_queue_combo(self, checked_queue_list=['ALL',]):
        """
        Set (initialize) self.group_tab_queue_combo.
        """
        self.group_tab_queue_combo.clear()

        queue_list = common_lsf.get_queue_list()
        queue_list = copy.deepcopy(queue_list)
        queue_list.sort()
        queue_list.insert(0, 'ALL')

        for queue in queue_list:
            self.group_tab_queue_combo.addCheckBoxItem(queue)

        # Set to checked status for checked_queue_list.
        for (i, qBox) in enumerate(self.group_tab_queue_combo.checkBoxList):
            if (qBox.text() in checked_queue_list) and (qBox.isChecked() is False):
                self.group_tab_queue_combo.checkBoxList[i].setChecked(True)

    def group_to_run_tab(self):
        """
        Get selected host_ip list, and jump to RUN tab, generate self.run_tab_table.
        """
        self.run_tab_host_dic = {}

        for row in range(self.group_tab_table.rowCount()):
            host_ip = self.group_tab_table.item(row, 1).text()
            host_name = self.group_tab_table.item(row, 2).text()
            self.run_tab_host_dic[host_ip] = {'host_name': host_name, 'state': Qt.Checked, 'output_message': ''}

        self.gen_run_tab_table()
        self.main_tab.setCurrentWidget(self.run_tab)

    def gen_group_tab_table(self):
        group_tab_table_dic = self.collect_group_tab_table_info()

        # self.group_tab_table
        self.group_tab_table.setShowGrid(True)
        self.group_tab_table.setSortingEnabled(True)
        self.group_tab_table.setColumnCount(0)
        self.group_tab_table.setColumnCount(5)
        self.group_tab_table_title_list = ['Group', 'Host_Ip', 'Host_Name', 'Ssh_Port', 'Queues']
        self.group_tab_table.setHorizontalHeaderLabels(self.group_tab_table_title_list)
        self.group_tab_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)

        # Fill self.group_tab_table items.
        host_line_num = 0

        for group in group_tab_table_dic.keys():
            host_line_num += len(group_tab_table_dic[group])

        self.group_tab_table.setRowCount(0)
        self.group_tab_table.setRowCount(host_line_num)

        i = -1

        for group in group_tab_table_dic.keys():
            for host_dic in group_tab_table_dic[group]:
                i += 1
                host_ip = host_dic['host_ip']
                host_name = host_dic['host_name']
                ssh_port = host_dic['ssh_port']
                queue_list = host_dic['queues']

                # Fill "Group" item.
                j = 0
                item = QTableWidgetItem(group)
                self.group_tab_table.setItem(i, j, item)

                # Fill "Host_Ip" item.
                j = j+1
                item = QTableWidgetItem(host_ip)
                self.group_tab_table.setItem(i, j, item)

                # Fill "Host_Name" item.
                j = j+1
                item = QTableWidgetItem(host_name)
                self.group_tab_table.setItem(i, j, item)

                # Fill "Ssh_Port" item.
                j = j+1
                item = QTableWidgetItem(ssh_port)
                self.group_tab_table.setItem(i, j, item)

                # Fill "Queueus" item.
                j = j+1
                item = QTableWidgetItem(' '.join(queue_list))
                self.group_tab_table.setItem(i, j, item)

        self.group_tab_table.resizeColumnsToContents()

    def collect_group_tab_table_info(self):
        """
        Collect host info with specified group/queue/host.
        group_tab_table_dic = {group: [{'host_name': host_name, 'ssh_port': ssh_port, 'queues': queue_list},
                                       {...},]
                              }
        """
        group_tab_table_dic = {}
        specified_group_list = self.group_tab_group_combo.currentText().strip().split()
        specified_queue_list = self.group_tab_queue_combo.currentText().strip().split()
        specified_host = self.group_tab_host_line.text().strip()

        if specified_group_list and specified_queue_list:
            for group in self.host_list_class.expanded_host_list_dic.keys():
                if ('ALL' in specified_group_list) or (group in specified_group_list):
                    group_tab_table_dic.setdefault(group, [])

                    for host_ip in self.host_list_class.expanded_host_list_dic[group].keys():
                        for host_name in self.host_list_class.expanded_host_list_dic[group][host_ip]['host_name']:
                            ssh_port = ''

                            if 'ssh_port' in self.host_list_class.expanded_host_list_dic[group][host_ip]:
                                ssh_port = self.host_list_class.expanded_host_list_dic[group][host_ip]['ssh_port']

                            host_queue_list = []

                            if host_name in self.host_queue_dic.keys():
                                host_queue_list = self.host_queue_dic[host_name]

                            if specified_host and (specified_host != host_ip) and (specified_host != host_name):
                                continue

                            if 'ALL' not in specified_queue_list:
                                continue_mark = True

                                for specified_queue in specified_queue_list:
                                    if specified_queue in host_queue_list:
                                        continue_mark = False
                                        break

                                if continue_mark:
                                    continue

                            group_tab_table_dic[group].append({'host_ip': host_ip, 'host_name': host_name, 'ssh_port': ssh_port, 'queues': host_queue_list})

        return group_tab_table_dic
# For group TAB (end) #

# For host TAB (begin) #
    def gen_host_tab(self):
        """
        Generate the HOST tab on batchRun GUI, show host_info.json informations.
        """
        # Init variables.
        (self.host_info_dic, group_list, server_type_list, os_list, cpu_architecture_list, cpu_thread_list, thread_per_core_list, cpu_model_list, cpu_frequency_list, mem_list) = self.get_host_tab_frame0_info()

        # self.host_tab
        self.host_tab_frame0 = QFrame(self.host_tab)
        self.host_tab_frame0.setFrameShadow(QFrame.Raised)
        self.host_tab_frame0.setFrameShape(QFrame.Box)

        self.host_tab_table = QTableWidget(self.host_tab)

        # self.host_tab - Grid
        host_tab_grid = QGridLayout()

        host_tab_grid.addWidget(self.host_tab_frame0, 0, 0)
        host_tab_grid.addWidget(self.host_tab_table, 1, 0)

        host_tab_grid.setRowStretch(0, 1)
        host_tab_grid.setRowStretch(1, 20)

        self.host_tab.setLayout(host_tab_grid)

        # Generate sub-frames
        self.gen_host_tab_frame0(group_list, server_type_list, os_list, cpu_architecture_list, cpu_thread_list, thread_per_core_list, cpu_model_list, cpu_frequency_list, mem_list)
        self.gen_host_tab_table()

    def get_host_tab_frame0_info(self):
        """
        Parse host_info_json and get basic information.
        """
        host_info_dic = {}
        group_list = copy.deepcopy(list(self.host_list_class.expanded_host_list_dic.keys()))
        server_type_list = []
        os_list = []
        cpu_architecture_list = []
        cpu_thread_list = []
        thread_per_core_list = []
        cpu_model_list = []
        cpu_frequency_list = []
        mem_list = []

        host_info_file = str(config.db_path) + '/host_info/host_info.json'

        if os.path.exists(host_info_file):
            with open(host_info_file, 'r') as HIF:
                host_info_dic = json.loads(HIF.read())

        if host_info_dic:
            for host_ip in host_info_dic.keys():
                if host_info_dic[host_ip]['server_type'] not in server_type_list:
                    server_type_list.append(host_info_dic[host_ip]['server_type'])

                if host_info_dic[host_ip]['os'] not in os_list:
                    os_list.append(host_info_dic[host_ip]['os'])

                if host_info_dic[host_ip]['cpu_architecture'] not in cpu_architecture_list:
                    cpu_architecture_list.append(host_info_dic[host_ip]['cpu_architecture'])

                if host_info_dic[host_ip]['cpu_thread'] not in cpu_thread_list:
                    cpu_thread_list.append(host_info_dic[host_ip]['cpu_thread'])

                if host_info_dic[host_ip]['thread_per_core'] not in thread_per_core_list:
                    thread_per_core_list.append(host_info_dic[host_ip]['thread_per_core'])

                if host_info_dic[host_ip]['cpu_model'] not in cpu_model_list:
                    cpu_model_list.append(host_info_dic[host_ip]['cpu_model'])

                if host_info_dic[host_ip]['cpu_frequency'] not in cpu_frequency_list:
                    cpu_frequency_list.append(host_info_dic[host_ip]['cpu_frequency'])

                if host_info_dic[host_ip]['mem_size'] not in mem_list:
                    mem_list.append(host_info_dic[host_ip]['mem_size'])

            # Sort list.
            group_list.sort()
            server_type_list.sort()
            os_list.sort()
            cpu_architecture_list.sort()
            cpu_thread_list.sort(key=int)
            thread_per_core_list.sort(key=int)
            cpu_model_list.sort()
            cpu_frequency_list.sort(key=float)
            mem_list.sort(key=int)

            # Switch string type.
            for i, cpu_thread in enumerate(cpu_thread_list):
                if cpu_thread == 0:
                    cpu_thread_list[i] = ''
                else:
                    cpu_thread_list[i] = str(cpu_thread)

            for i, thread_per_core in enumerate(thread_per_core_list):
                if thread_per_core == 0:
                    thread_per_core_list[i] = ''
                else:
                    thread_per_core_list[i] = str(thread_per_core)

            for i, cpu_frequency in enumerate(cpu_frequency_list):
                if cpu_frequency == 0.0:
                    cpu_frequency_list[i] = ''
                else:
                    cpu_frequency_list[i] = str(cpu_frequency)

            for i, mem in enumerate(mem_list):
                if mem == 0:
                    mem_list[i] = ''
                else:
                    mem_list[i] = str(mem)

        return host_info_dic, group_list, server_type_list, os_list, cpu_architecture_list, cpu_thread_list, thread_per_core_list, cpu_model_list, cpu_frequency_list, mem_list

    def gen_host_tab_frame0(self, group_list, server_type_list, os_list, cpu_architecture_list, cpu_thread_list, thread_per_core_list, cpu_model_list, cpu_frequency_list, mem_list):
        # self.host_tab_frame0
        # "Group" item.
        host_tab_group_label = QLabel('Group', self.host_tab_frame0)
        host_tab_group_label.setStyleSheet("font-weight: bold;")
        host_tab_group_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_group_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_group_combo, item_list=group_list)

        # "Server_Type" item.
        host_tab_server_type_label = QLabel('Server_Type', self.host_tab_frame0)
        host_tab_server_type_label.setStyleSheet("font-weight: bold;")
        host_tab_server_type_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_server_type_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_server_type_combo, item_list=server_type_list)

        # "OS" item.
        host_tab_os_label = QLabel('OS', self.host_tab_frame0)
        host_tab_os_label.setStyleSheet("font-weight: bold;")
        host_tab_os_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_os_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_os_combo, item_list=os_list)

        # "Cpu_Arch" item.
        host_tab_cpu_architecture_label = QLabel('Cpu_Arch', self.host_tab_frame0)
        host_tab_cpu_architecture_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_architecture_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_architecture_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_cpu_architecture_combo, item_list=cpu_architecture_list)

        # "Cpu_Model" item.
        host_tab_cpu_model_label = QLabel('Cpu_Model', self.host_tab_frame0)
        host_tab_cpu_model_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_model_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_model_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_cpu_model_combo, item_list=cpu_model_list)

        # "Cpu_Thread" item.
        host_tab_cpu_thread_label = QLabel('Cpu_Thread', self.host_tab_frame0)
        host_tab_cpu_thread_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_thread_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_thread_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_cpu_thread_combo, item_list=cpu_thread_list)

        # "Thread_Per_Core" item.
        host_tab_thread_per_core_label = QLabel('Thread_Per_Core', self.host_tab_frame0)
        host_tab_thread_per_core_label.setStyleSheet("font-weight: bold;")
        host_tab_thread_per_core_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_thread_per_core_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_thread_per_core_combo, item_list=thread_per_core_list)

        # "Cpu_Freq" item.
        host_tab_cpu_frequency_label = QLabel('Cpu_Freq', self.host_tab_frame0)
        host_tab_cpu_frequency_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_frequency_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_frequency_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_cpu_frequency_combo, item_list=cpu_frequency_list)

        # "MEM" item.
        host_tab_mem_label = QLabel('MEM', self.host_tab_frame0)
        host_tab_mem_label.setStyleSheet("font-weight: bold;")
        host_tab_mem_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_mem_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_combo(combo_instance=self.host_tab_mem_combo, item_list=mem_list)

        # "Host" item.
        host_tab_host_label = QLabel('Host', self.host_tab_frame0)
        host_tab_host_label.setStyleSheet("font-weight: bold;")
        host_tab_host_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_host_line = QLineEdit()
        self.host_tab_host_line.returnPressed.connect(self.gen_host_tab_table)

        host_tab_host_line_completer = common_pyqt5.get_completer(self.completer_host_list)
        self.host_tab_host_line.setCompleter(host_tab_host_line_completer)

        # empty item.
        host_tab_empty_label = QLabel('', self.group_tab_frame0)

        # "Check" button.
        host_tab_check_button = QPushButton('Check', self.host_tab_frame0)
        host_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        host_tab_check_button.clicked.connect(self.gen_host_tab_table)

        # "toRun" button.
        host_tab_torun_button = QPushButton('toRun', self.host_tab_frame0)
        host_tab_torun_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        host_tab_torun_button.clicked.connect(self.host_to_run_tab)

        # self.host_tab_frame0 - Grid
        host_tab_frame0_grid = QGridLayout()

        host_tab_frame0_grid.addWidget(host_tab_group_label, 0, 0)
        host_tab_frame0_grid.addWidget(self.host_tab_group_combo, 0, 1)
        host_tab_frame0_grid.addWidget(host_tab_server_type_label, 0, 2)
        host_tab_frame0_grid.addWidget(self.host_tab_server_type_combo, 0, 3)
        host_tab_frame0_grid.addWidget(host_tab_os_label, 0, 4)
        host_tab_frame0_grid.addWidget(self.host_tab_os_combo, 0, 5)
        host_tab_frame0_grid.addWidget(host_tab_cpu_architecture_label, 0, 6)
        host_tab_frame0_grid.addWidget(self.host_tab_cpu_architecture_combo, 0, 7)
        host_tab_frame0_grid.addWidget(host_tab_cpu_model_label, 0, 8)
        host_tab_frame0_grid.addWidget(self.host_tab_cpu_model_combo, 0, 9)
        host_tab_frame0_grid.addWidget(host_tab_empty_label, 0, 10)
        host_tab_frame0_grid.addWidget(host_tab_check_button, 0, 11)
        host_tab_frame0_grid.addWidget(host_tab_cpu_thread_label, 1, 0)
        host_tab_frame0_grid.addWidget(self.host_tab_cpu_thread_combo, 1, 1)
        host_tab_frame0_grid.addWidget(host_tab_thread_per_core_label, 1, 2)
        host_tab_frame0_grid.addWidget(self.host_tab_thread_per_core_combo, 1, 3)
        host_tab_frame0_grid.addWidget(host_tab_cpu_frequency_label, 1, 4)
        host_tab_frame0_grid.addWidget(self.host_tab_cpu_frequency_combo, 1, 5)
        host_tab_frame0_grid.addWidget(host_tab_mem_label, 1, 6)
        host_tab_frame0_grid.addWidget(self.host_tab_mem_combo, 1, 7)
        host_tab_frame0_grid.addWidget(host_tab_host_label, 1, 8)
        host_tab_frame0_grid.addWidget(self.host_tab_host_line, 1, 9)
        host_tab_frame0_grid.addWidget(host_tab_empty_label, 1, 10)
        host_tab_frame0_grid.addWidget(host_tab_torun_button, 1, 11)

        host_tab_frame0_grid.setColumnStretch(0, 1)
        host_tab_frame0_grid.setColumnStretch(1, 1)
        host_tab_frame0_grid.setColumnStretch(2, 1)
        host_tab_frame0_grid.setColumnStretch(3, 1)
        host_tab_frame0_grid.setColumnStretch(4, 1)
        host_tab_frame0_grid.setColumnStretch(5, 1)
        host_tab_frame0_grid.setColumnStretch(6, 1)
        host_tab_frame0_grid.setColumnStretch(7, 1)
        host_tab_frame0_grid.setColumnStretch(8, 1)
        host_tab_frame0_grid.setColumnStretch(9, 1)
        host_tab_frame0_grid.setColumnStretch(10, 1)
        host_tab_frame0_grid.setColumnStretch(11, 1)

        self.host_tab_frame0.setLayout(host_tab_frame0_grid)

    def set_host_tab_combo(self, combo_instance, item_list=[], checked_item_list=['ALL',]):
        """
        Set (initialize) combo instance on self.host_tab_frame0.
        """
        combo_instance.clear()
        item_list.insert(0, 'ALL')

        for item in item_list:
            combo_instance.addCheckBoxItem(item)

        # Set to checked status for checked_queue_list.
        for (i, qBox) in enumerate(combo_instance.checkBoxList):
            if (qBox.text() in checked_item_list) and (qBox.isChecked() is False):
                combo_instance.checkBoxList[i].setChecked(True)

    def host_to_run_tab(self):
        """
        Get selected host_ip list, and jump to RUN tab, generate self.run_tab_table.
        """
        self.run_tab_host_dic = {}

        for row in range(self.host_tab_table.rowCount()):
            host_ip = self.host_tab_table.item(row, 0).text()
            host_name = self.host_tab_table.item(row, 1).text()
            self.run_tab_host_dic[host_ip] = {'host_name': host_name, 'state': Qt.Checked, 'output_message': ''}

        self.gen_run_tab_table()
        self.main_tab.setCurrentWidget(self.run_tab)

    def gen_host_tab_table(self):
        host_tab_table_dic = self.collect_host_tab_table_info()

        # self.host_tab_table
        self.host_tab_table.setShowGrid(True)
        self.host_tab_table.setSortingEnabled(True)
        self.host_tab_table.setColumnCount(0)
        self.host_tab_table.setColumnCount(11)
        self.host_tab_table_title_list = ['Host_Ip', 'Host_Name', 'Group', 'Server_Type', 'OS', 'Cpu_Arch', 'Cpu_Model', 'Cpu_Thread', 'Thread_Per_Core', 'Cpu_Freq (GHz)', 'MEM (GB)']
        self.host_tab_table.setHorizontalHeaderLabels(self.host_tab_table_title_list)

        self.host_tab_table.setColumnWidth(0, 120)
        self.host_tab_table.setColumnWidth(3, 100)
        self.host_tab_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.host_tab_table.setColumnWidth(5, 80)
        self.host_tab_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.host_tab_table.setColumnWidth(7, 100)
        self.host_tab_table.setColumnWidth(8, 130)
        self.host_tab_table.setColumnWidth(9, 120)
        self.host_tab_table.setColumnWidth(10, 80)

        # Fill self.host_tab_table items.
        self.host_tab_table.setRowCount(0)
        self.host_tab_table.setRowCount(len(host_tab_table_dic))

        i = -1

        for host_ip in host_tab_table_dic.keys():
            group_list = host_tab_table_dic[host_ip]['groups']
            host_name = host_tab_table_dic[host_ip]['host_name']
            server_type = host_tab_table_dic[host_ip].get('server_type', '')
            os = host_tab_table_dic[host_ip].get('os', '')
            cpu_architecture = host_tab_table_dic[host_ip].get('cpu_architecture', '')
            cpu_thread = host_tab_table_dic[host_ip].get('cpu_thread', 0)
            thread_per_core = host_tab_table_dic[host_ip].get('thread_per_core', 0)
            cpu_model = host_tab_table_dic[host_ip].get('cpu_model', '')
            cpu_frequency = host_tab_table_dic[host_ip].get('cpu_frequency', 0.0)
            mem_size = host_tab_table_dic[host_ip].get('mem_size', 0)

            i += 1

            # Fill "Host_Ip" item.
            j = 0
            item = QTableWidgetItem(host_ip)
            self.host_tab_table.setItem(i, j, item)

            # Fill "Host_Name" item.
            j += 1

            if isinstance(host_name, list):
                item = QTableWidgetItem(' '.join(host_name))
            else:
                item = QTableWidgetItem(host_name)

            self.host_tab_table.setItem(i, j, item)

            # Fill "Group" item.
            j += 1
            item = QTableWidgetItem(' '.join(group_list))
            self.host_tab_table.setItem(i, j, item)

            # Fill "Server_Type" item.
            j += 1
            item = QTableWidgetItem(server_type)

            if not server_type:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "OS" item.
            j += 1
            item = QTableWidgetItem(os)

            if not os:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "Cpu_Arch" item.
            j += 1
            item = QTableWidgetItem(cpu_architecture)

            if not cpu_architecture:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "Cpu_Model" item.
            j += 1
            item = QTableWidgetItem(cpu_model)

            if not cpu_model:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "Cpu_Thread" item.
            j += 1
            item = QTableWidgetItem()

            if cpu_thread:
                item.setData(Qt.DisplayRole, cpu_thread)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "Thread_Per_Core" item.
            j += 1
            item = QTableWidgetItem()

            if thread_per_core:
                item.setData(Qt.DisplayRole, thread_per_core)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "Cpu_Freq" item.
            j += 1
            item = QTableWidgetItem()

            if cpu_frequency:
                item.setData(Qt.DisplayRole, cpu_frequency)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "MEM" item.
            j += 1
            item = QTableWidgetItem()

            if mem_size:
                item.setData(Qt.DisplayRole, mem_size)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

    def collect_host_tab_table_info(self):
        """
        Collect host info with specified group/server_type/os/cpu_architecture/cpu_model/cpu_thread/thread_per_core/cpu_frequency/mem/host.
        """
        host_tab_table_dic = {}
        specified_group_list = self.host_tab_group_combo.currentText().strip().split()
        specified_server_type_list = self.host_tab_server_type_combo.currentText().strip().split()
        specified_os = self.host_tab_os_combo.currentText().strip()
        specified_cpu_architecture_list = self.host_tab_cpu_architecture_combo.currentText().strip().split()
        specified_cpu_model = self.host_tab_cpu_model_combo.currentText().strip()
        specified_cpu_thread_list = self.host_tab_cpu_thread_combo.currentText().strip().split()
        specified_thread_per_core_list = self.host_tab_thread_per_core_combo.currentText().strip().split()
        specified_cpu_frequency_list = self.host_tab_cpu_frequency_combo.currentText().strip().split()
        specified_mem_list = self.host_tab_mem_combo.currentText().strip().split()
        specified_host = self.host_tab_host_line.text().strip()

        # Preprocess int/float items.
        for item_list in [specified_cpu_thread_list, specified_thread_per_core_list, specified_mem_list]:
            for i, item in enumerate(item_list):
                if not item:
                    item_list[i] = 0
                elif item != 'ALL':
                    item_list[i] = int(item)

        for i, specified_cpu_frequency in enumerate(specified_cpu_frequency_list):
            if not specified_cpu_frequency:
                specified_cpu_frequency_list[i] = 0.0
            elif specified_cpu_frequency != 'ALL':
                specified_cpu_frequency_list[i] = float(specified_cpu_frequency)

        for host_ip in self.host_list_class.host_ip_dic.keys():
            if 'ALL' not in specified_group_list:
                continue_mark = True

                for specified_group in specified_group_list:
                    if specified_group in self.host_group_relationship_dic[host_ip]:
                        continue_mark = False

                if continue_mark:
                    continue

            if host_ip not in self.host_info_dic:
                continue
            else:
                if 'ALL' not in specified_server_type_list:
                    if ((not self.host_info_dic[host_ip]['server_type']) and specified_server_type_list) or (self.host_info_dic[host_ip]['server_type'] and (self.host_info_dic[host_ip]['server_type'] not in specified_server_type_list)):
                        continue

                if 'ALL' not in specified_os:
                    if ((not self.host_info_dic[host_ip]['os']) and specified_os) or (self.host_info_dic[host_ip]['os'] and (self.host_info_dic[host_ip]['os'] not in specified_os)):
                        continue

                if 'ALL' not in specified_cpu_architecture_list:
                    if ((not self.host_info_dic[host_ip]['cpu_architecture']) and specified_cpu_architecture_list) or (self.host_info_dic[host_ip]['cpu_architecture'] and (self.host_info_dic[host_ip]['cpu_architecture'] not in specified_cpu_architecture_list)):
                        continue

                if 'ALL' not in specified_cpu_model:
                    if ((not self.host_info_dic[host_ip]['cpu_model']) and specified_cpu_model) or (self.host_info_dic[host_ip]['cpu_model'] and (self.host_info_dic[host_ip]['cpu_model'] not in specified_cpu_model)):
                        continue

                if 'ALL' not in specified_cpu_thread_list:
                    if ((not self.host_info_dic[host_ip]['cpu_thread']) and specified_cpu_thread_list) or (self.host_info_dic[host_ip]['cpu_thread'] and (self.host_info_dic[host_ip]['cpu_thread'] not in specified_cpu_thread_list)):
                        continue

                if 'ALL' not in specified_thread_per_core_list:
                    if ((not self.host_info_dic[host_ip]['thread_per_core']) and specified_thread_per_core_list) or (self.host_info_dic[host_ip]['thread_per_core'] and (self.host_info_dic[host_ip]['thread_per_core'] not in specified_thread_per_core_list)):
                        continue

                if 'ALL' not in specified_cpu_frequency_list:
                    if ((not self.host_info_dic[host_ip]['cpu_frequency']) and specified_cpu_frequency_list) or (self.host_info_dic[host_ip]['cpu_frequency'] and (self.host_info_dic[host_ip]['cpu_frequency'] not in specified_cpu_frequency_list)):
                        continue

                if 'ALL' not in specified_mem_list:
                    if ((not self.host_info_dic[host_ip]['mem_size']) and specified_mem_list) or (self.host_info_dic[host_ip]['mem_size'] and (self.host_info_dic[host_ip]['mem_size'] not in specified_mem_list)):
                        continue

                if specified_host and ((specified_host != host_ip) and (specified_host not in self.host_list_class.host_ip_dic[host_ip]['host_name'])):
                    continue

                host_tab_table_dic.setdefault(host_ip, self.host_list_class.host_ip_dic[host_ip])
                host_tab_table_dic[host_ip].update(self.host_info_dic[host_ip])

        # Update groups setting for host_ip.
        for host_ip in host_tab_table_dic.keys():
            host_tab_table_dic[host_ip]['groups'] = self.host_group_relationship_dic[host_ip]

        return host_tab_table_dic
# For host TAB (end) #

# For run TAB (begin) #
    def gen_run_tab(self):
        """
        Generate the RUN tab on batchRun GUI, run specified command and show command output message.
        """
        # self.run_tab
        self.run_tab_frame0 = QFrame(self.run_tab)
        self.run_tab_frame0.setFrameShadow(QFrame.Raised)
        self.run_tab_frame0.setFrameShape(QFrame.Box)

        self.run_tab_frame1 = QFrame(self.run_tab)
        self.run_tab_frame1.setFrameShadow(QFrame.Raised)
        self.run_tab_frame1.setFrameShape(QFrame.Box)

        self.run_tab_frame2 = QFrame(self.run_tab)
        self.run_tab_frame2.setFrameShadow(QFrame.Raised)
        self.run_tab_frame2.setFrameShape(QFrame.Box)

        self.run_tab_table = QTableWidget(self.run_tab)
        self.run_tab_table.horizontalHeader().sectionClicked.connect(self.click_run_tab_table_header)
        self.run_tab_table.itemClicked.connect(self.run_tab_table_item_clicked)

        # self.run_tab - Grid
        run_tab_left_container = QWidget()
        run_tab_left_grid = QGridLayout()
        run_tab_left_grid.addWidget(self.run_tab_frame0, 0, 0)
        run_tab_left_grid.addWidget(self.run_tab_table, 1, 0)
        run_tab_left_grid.addWidget(self.run_tab_frame1, 2, 0)
        run_tab_left_grid.setRowStretch(0, 1)
        run_tab_left_grid.setRowStretch(1, 10)
        run_tab_left_grid.setRowStretch(2, 2)
        run_tab_left_container.setLayout(run_tab_left_grid)

        run_tab_right_container = QWidget()
        run_tab_right_grid = QGridLayout()
        run_tab_right_grid.addWidget(self.run_tab_frame2, 0, 0)
        run_tab_right_container.setLayout(run_tab_right_grid)

        run_tab_splitter = QSplitter(Qt.Horizontal)
        run_tab_splitter.setHandleWidth(1)
        run_tab_splitter.addWidget(run_tab_left_container)
        run_tab_splitter.addWidget(run_tab_right_container)

        total_width = self.width()
        left_width = int(total_width * 2 / 3)
        right_width = total_width - left_width
        run_tab_splitter.setSizes([left_width, right_width])

        run_tab_grid = QGridLayout()
        run_tab_grid.addWidget(run_tab_splitter, 0, 0)
        self.run_tab.setLayout(run_tab_grid)

        # Generate sub-frames
        self.gen_run_tab_frame0()
        self.gen_run_tab_frame1()
        self.gen_run_tab_frame2()
        self.gen_run_tab_table()

    def gen_run_tab_frame0(self):
        # self.run_tab_frame0
        # "Timeout" item.
        run_tab_timeout_label = QLabel('Timeout', self.run_tab_frame0)
        run_tab_timeout_label.setStyleSheet("font-weight: bold;")
        run_tab_timeout_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.run_tab_timeout_line = QLineEdit()
        self.run_tab_timeout_line.setText(str(config.parallel_timeout))

        # "Command" item.
        run_tab_command_label = QLabel('Command :', self.run_tab_frame0)
        run_tab_command_label.setStyleSheet("font-weight: bold;")
        run_tab_command_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.run_tab_command_line = QLineEdit()
        self.run_tab_command_line.returnPressed.connect(self.run_tab_run_command)

        # empty item.
        run_tab_empty_label = QLabel('', self.run_tab_frame0)

        # "Run" button.
        run_tab_run_button = QPushButton('Run', self.run_tab_frame0)
        run_tab_run_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        run_tab_run_button.clicked.connect(self.run_tab_run_command)

        # self.run_tab_frame0 - Grid
        run_tab_frame0_grid = QGridLayout()

        run_tab_frame0_grid.addWidget(run_tab_timeout_label, 0, 0)
        run_tab_frame0_grid.addWidget(self.run_tab_timeout_line, 0, 1)
        run_tab_frame0_grid.addWidget(run_tab_empty_label, 0, 2)
        run_tab_frame0_grid.addWidget(run_tab_command_label, 0, 3)
        run_tab_frame0_grid.addWidget(self.run_tab_command_line, 0, 4)
        run_tab_frame0_grid.addWidget(run_tab_empty_label, 0, 5)
        run_tab_frame0_grid.addWidget(run_tab_run_button, 0, 6)

        run_tab_frame0_grid.setColumnStretch(0, 2)
        run_tab_frame0_grid.setColumnStretch(1, 2)
        run_tab_frame0_grid.setColumnStretch(2, 1)
        run_tab_frame0_grid.setColumnStretch(3, 2)
        run_tab_frame0_grid.setColumnStretch(4, 16)
        run_tab_frame0_grid.setColumnStretch(5, 1)
        run_tab_frame0_grid.setColumnStretch(6, 2)

        self.run_tab_frame0.setLayout(run_tab_frame0_grid)

    def gen_run_tab_table(self):
        """
        Generate self.run_tab_tale with self.run_tab_host_dic.
        """
        # self.run_tab_table
        self.run_tab_table.setShowGrid(True)
        self.run_tab_table.setSortingEnabled(False)
        self.run_tab_table.setColumnCount(0)
        self.run_tab_table.setColumnCount(3)
        self.run_tab_table_title_list = ['Host_Ip', 'Host_Name', 'Command_Output_Message']
        self.run_tab_table.setHorizontalHeaderLabels(self.run_tab_table_title_list)

        self.run_tab_table.setColumnWidth(0, 160)
        self.run_tab_table.setColumnWidth(1, 130)
        self.run_tab_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

        # Fill self.run_tab_table items.
        self.run_tab_table.setRowCount(0)
        self.run_tab_table.setRowCount(len(self.run_tab_host_dic.keys()))

        i = -1

        for host_ip in self.run_tab_host_dic.keys():
            host_name = self.run_tab_host_dic[host_ip]['host_name']
            output_message = self.run_tab_host_dic[host_ip]['output_message']
            i += 1

            # Fill "Host_Ip" item.
            j = 0
            item = QTableWidgetItem(host_ip)
            item.setCheckState(self.run_tab_host_dic[host_ip]['state'])
            self.run_tab_table.setItem(i, j, item)

            # Fill "Host_Name" item.
            j += 1
            item = QTableWidgetItem(host_name)
            self.run_tab_table.setItem(i, j, item)

            # Fill "Command_Output_Message" item.
            j += 1
            item = QTableWidgetItem(output_message)
            self.run_tab_table.setItem(i, j, item)

    def click_run_tab_table_header(self, index):
        """
        Select or Un-select all host_ip(s) on self.run_tab_table when clicking "Host_Ip" title header.
        """
        if index == 0:
            first_host_ip_item_state = self.run_tab_table.item(0, 0).checkState()

            if first_host_ip_item_state == Qt.Checked:
                new_state = Qt.Unchecked
                self.update_run_tab_frame1('* Un-select all host_ip(s).')
            else:
                new_state = Qt.Checked
                self.update_run_tab_frame1('* Select all host_ip(s).')

            for row in range(self.run_tab_table.rowCount()):
                self.run_tab_table.item(row, 0).setCheckState(new_state)
                host_ip = self.run_tab_table.item(row, 0).text().strip()
                self.run_tab_host_dic[host_ip]['state'] = new_state

    def run_tab_table_item_clicked(self, item):
        """
        If item changed on self.run_tab_table, update host_ip state setting.
        """
        if item.column() == 0:
            host_ip = item.text().strip()

            if self.run_tab_host_dic[host_ip]['state'] != item.checkState():
                self.run_tab_host_dic[host_ip]['state'] = item.checkState()

                if item.checkState() == Qt.Checked:
                    self.update_run_tab_frame1('* host_ip "' + str(host_ip) + '" is selected.')
                else:
                    self.update_run_tab_frame1('* host_ip "' + str(host_ip) + '" is un-selected.')

    def run_tab_run_command(self):
        """
        Run command on specified host(s) with batch_run, then update self.run_tab_table.
        """
        run_command = self.run_tab_command_line.text().strip()

        if run_command:
            # Check timeout setting.
            timeout = self.run_tab_timeout_line.text().strip()

            if not re.match(r'^\d+$', timeout):
                self.update_run_tab_frame1('*Error*: Wrong format of Timeout "' + str(timeout) + '", it must be an integer.', color='red')
                return

            # Create current run dir.
            tmp_batchRun_dir = '/tmp/batchRun'
            tmp_batchRun_user_dir = str(tmp_batchRun_dir) + '/' + str(CURRENT_USER)
            current_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            tmp_batchRun_user_current_dir = str(tmp_batchRun_dir) + '/' + str(CURRENT_USER) + '/' + str(current_time)

            if not os.path.exists(tmp_batchRun_user_current_dir):
                if not os.path.exists(tmp_batchRun_user_dir):
                    if not os.path.exists(tmp_batchRun_dir):
                        common.create_dir(tmp_batchRun_dir, permission=0o1777)

                    common.create_dir(tmp_batchRun_user_dir, permission=0o700)

                common.create_dir(tmp_batchRun_user_current_dir, permission=0o777)

            # Save host list.
            host_list_file = str(tmp_batchRun_user_current_dir) + '/host.list'
            run_tab_selected_host_ip_list = []

            with open(host_list_file, 'a') as HLF:
                for host_ip in self.run_tab_host_dic.keys():
                    if self.run_tab_host_dic[host_ip]['state'] == Qt.Checked:
                        HLF.write(str(host_ip) + '\n')
                        run_tab_selected_host_ip_list.append(host_ip)

            # Call batch_run to execute specified command.
            self.update_run_tab_frame1('* Run command "' + str(run_command) + '" parallel with below batch_run command.')

            output_file = str(tmp_batchRun_user_current_dir) + '/HOST'
            batch_run_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run --hosts ' + str(host_list_file) + ' --command \"' + str(run_command) + '\" --parallel ' + str(len(run_tab_selected_host_ip_list)) + ' --timeout ' + str(timeout) + ' --output_message_level 1 --output_file ' + str(output_file)

            my_show_message = ShowMessage('Info', '快马加鞭X' + str(len(run_tab_selected_host_ip_list)) + ', running ...')
            my_show_message.start()
            self.update_run_tab_frame1('  ' + str(batch_run_command))
            os.system(batch_run_command)
            self.update_run_tab_frame1('  Done')
            my_show_message.terminate()

            # Clean up 'output_message' on self.run_tab_host_dic.
            for host_ip in self.run_tab_host_dic.keys():
                self.run_tab_host_dic[host_ip]['output_message'] = ''

            # Collect command output message.
            for file_name in os.listdir(tmp_batchRun_user_current_dir):
                if file_name in self.run_tab_host_dic:
                    file_path = str(tmp_batchRun_user_current_dir) + '/' + str(file_name)

                    with open(file_path, 'r') as FP:
                        self.run_tab_host_dic[file_name]['output_message'] = FP.read().strip()

            # Update self.run_tab_table.
            for row in range(self.run_tab_table.rowCount()):
                host_ip = self.run_tab_table.item(row, 0).text().strip()
                self.run_tab_table.item(row, 2).setText(self.run_tab_host_dic[host_ip]['output_message'])

                if 'pexpect.exceptions.TIMEOUT' in self.run_tab_host_dic[host_ip]['output_message']:
                    self.run_tab_table.item(row, 2).setForeground(QBrush(Qt.red))
                    self.update_run_tab_frame1('*Error*: Host "' + str(self.run_tab_table.item(row, 0).text().strip()) + '" ssh timeout.', color='red')
                elif (run_command == 'hostname') and (self.run_tab_host_dic[host_ip]['output_message'] != self.run_tab_table.item(row, 1).text().strip()):
                    self.run_tab_table.item(row, 2).setForeground(QBrush(Qt.red))
                    self.update_run_tab_frame1('*Warning*: Host "' + str(self.run_tab_table.item(row, 0).text().strip()) + '", hostname is "' + str(self.run_tab_table.item(row, 1).text().strip()) + '" in host.list, but "' + str(self.run_tab_host_dic[host_ip]['output_message']) + '" with hostname command.', color='yellow')
                else:
                    self.run_tab_table.item(row, 2).setForeground(QBrush(Qt.white))

    def gen_run_tab_frame1(self):
        # self.run_tab_frame1
        self.run_tab_log_text = QTextEdit(self.run_tab_frame1)

        # self.run_tab_frame1 - Grid
        run_tab_frame1_grid = QGridLayout()
        run_tab_frame1_grid.addWidget(self.run_tab_log_text, 0, 0)
        self.run_tab_frame1.setLayout(run_tab_frame1_grid)

    def update_run_tab_frame1(self, message, color='white'):
        """
        self.update self.run_tab_log_text with specified message.
        """
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        full_message = '[' + str(current_time) + '] ' + str(message) + '\n'

        if color:
            color_format = self.run_tab_log_text.currentCharFormat()
            color_format.setForeground(QColor(color))
            self.run_tab_log_text.setCurrentCharFormat(color_format)

        self.run_tab_log_text.insertPlainText(full_message)
        common_pyqt5.text_edit_visible_position(self.run_tab_log_text, 'End')

    def gen_run_tab_frame2(self):
        run_tab_frame2_grid = QGridLayout()
        self.xterm_widget = XtermWidget()
        run_tab_frame2_grid.addWidget(self.xterm_widget, 0, 0)
        self.run_tab_frame2.setLayout(run_tab_frame2_grid)
# For run TAB (end) #

# For log TAB (begin) #
    def gen_log_tab(self):
        """
        Generate the LOG tab on batchRun GUI, show history command and log detail.
        """
        # self.log_tab
        self.log_tab_frame0 = QFrame(self.log_tab)
        self.log_tab_frame0.setFrameShadow(QFrame.Raised)
        self.log_tab_frame0.setFrameShape(QFrame.Box)

        self.log_tab_frame1 = QFrame(self.log_tab)
        self.log_tab_frame1.setFrameShadow(QFrame.Raised)
        self.log_tab_frame1.setFrameShape(QFrame.Box)

        self.log_tab_table = QTableWidget(self.log_tab)
        self.log_tab_table.itemClicked.connect(self.log_tab_check_click)

        # self.log_tab - Grid
        log_tab_left_container = QWidget()
        log_tab_left_grid = QGridLayout()
        log_tab_left_grid.addWidget(self.log_tab_frame0, 0, 0)
        log_tab_left_grid.addWidget(self.log_tab_table, 1, 0)
        log_tab_left_grid.setRowStretch(0, 1)
        log_tab_left_grid.setRowStretch(1, 20)
        log_tab_left_container.setLayout(log_tab_left_grid)

        log_tab_right_container = QWidget()
        log_tab_right_grid = QGridLayout()
        log_tab_right_grid.addWidget(self.log_tab_frame1, 0, 0)
        log_tab_right_container.setLayout(log_tab_right_grid)

        log_tab_splitter = QSplitter(Qt.Horizontal)
        log_tab_splitter.setHandleWidth(1)
        log_tab_splitter.addWidget(log_tab_left_container)
        log_tab_splitter.addWidget(log_tab_right_container)

        total_width = self.width()
        left_width = int(total_width * 2 / 3)
        right_width = total_width - left_width
        log_tab_splitter.setSizes([left_width, right_width])

        log_tab_grid = QGridLayout()
        log_tab_grid.addWidget(log_tab_splitter, 0, 0)
        self.log_tab.setLayout(log_tab_grid)

        # Generate sub-frames
        self.gen_log_tab_frame0()
        self.gen_log_tab_table()
        self.gen_log_tab_frame1()

    def log_tab_check_click(self, item=None):
        """
        If click the log icon, show log content on self.log_tab_frame1.
        """
        if item is not None:
            if item.column() == 4:
                current_row = self.log_tab_table.currentRow()
                log_file = self.log_dic_list[current_row]['log']

                if os.path.exists(log_file):
                    with open(log_file, 'r') as LF:
                        log_content = LF.read()
                        self.update_log_tab_frame1(log_content)

    def gen_log_tab_frame0(self):
        # self.log_tab_frame0
        # "User" item.
        log_tab_user_label = QLabel('User', self.log_tab_frame0)
        log_tab_user_label.setStyleSheet("font-weight: bold;")
        log_tab_user_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.log_tab_user_combo = common_pyqt5.QComboCheckBox(self.log_tab_frame0)
        self.set_log_tab_user_combo()

        # "Begin_Date" item.
        log_tab_begin_date_label = QLabel('Begin_Date', self.log_tab_frame0)
        log_tab_begin_date_label.setStyleSheet("font-weight: bold;")
        log_tab_begin_date_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.log_tab_begin_date_edit = QDateEdit(self.log_tab_frame0)
        self.log_tab_begin_date_edit.setDisplayFormat('yyyy-MM-dd')
        self.log_tab_begin_date_edit.setMinimumDate(QDate.currentDate().addDays(-3652))
        self.log_tab_begin_date_edit.setCalendarPopup(True)
        self.log_tab_begin_date_edit.setDate(QDate.currentDate().addDays(-7))

        # "End_Date" item.
        log_tab_end_date_label = QLabel('End_Date', self.log_tab_frame0)
        log_tab_end_date_label.setStyleSheet("font-weight: bold;")
        log_tab_end_date_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.log_tab_end_date_edit = QDateEdit(self.log_tab_frame0)
        self.log_tab_end_date_edit.setDisplayFormat('yyyy-MM-dd')
        self.log_tab_end_date_edit.setMinimumDate(QDate.currentDate().addDays(-3652))
        self.log_tab_end_date_edit.setCalendarPopup(True)
        self.log_tab_end_date_edit.setDate(QDate.currentDate())

        # "Info" item.
        log_tab_info_label = QLabel('Info', self.log_tab_frame0)
        log_tab_info_label.setStyleSheet("font-weight: bold;")
        log_tab_info_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.log_tab_info_line = QLineEdit()
        self.log_tab_info_line.returnPressed.connect(self.gen_log_tab_table)

        # "Search" button.
        log_tab_search_button = QPushButton('Search', self.log_tab_frame0)
        log_tab_search_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        log_tab_search_button.clicked.connect(self.gen_log_tab_table)

        # self.log_tab_frame0 - Grid
        log_tab_frame0_grid = QGridLayout()

        log_tab_frame0_grid.addWidget(log_tab_user_label, 0, 0)
        log_tab_frame0_grid.addWidget(self.log_tab_user_combo, 0, 1)
        log_tab_frame0_grid.addWidget(log_tab_begin_date_label, 0, 2)
        log_tab_frame0_grid.addWidget(self.log_tab_begin_date_edit, 0, 3)
        log_tab_frame0_grid.addWidget(log_tab_end_date_label, 0, 4)
        log_tab_frame0_grid.addWidget(self.log_tab_end_date_edit, 0, 5)
        log_tab_frame0_grid.addWidget(log_tab_info_label, 0, 6)
        log_tab_frame0_grid.addWidget(self.log_tab_info_line, 0, 7)
        log_tab_frame0_grid.addWidget(log_tab_search_button, 0, 8)

        log_tab_frame0_grid.setColumnStretch(0, 2)
        log_tab_frame0_grid.setColumnStretch(1, 3)
        log_tab_frame0_grid.setColumnStretch(2, 2)
        log_tab_frame0_grid.setColumnStretch(3, 2)
        log_tab_frame0_grid.setColumnStretch(4, 2)
        log_tab_frame0_grid.setColumnStretch(5, 2)
        log_tab_frame0_grid.setColumnStretch(6, 2)
        log_tab_frame0_grid.setColumnStretch(7, 4)
        log_tab_frame0_grid.setColumnStretch(8, 2)

        self.log_tab_frame0.setLayout(log_tab_frame0_grid)

    def set_log_tab_user_combo(self, checked_user_list=['ALL',]):
        """
        Set (initialize) self.log_tab_user_combo.
        """
        self.log_tab_user_combo.clear()
        user_list = self.get_log_user_list()

        if len(user_list) == 1:
            checked_user_list = [user_list[0]]
        else:
            user_list.sort()
            user_list.insert(0, 'ALL')

        for user in user_list:
            self.log_tab_user_combo.addCheckBoxItem(user)

        # Set to checked status for checked_queue_list.
        for (i, qBox) in enumerate(self.log_tab_user_combo.checkBoxList):
            if (qBox.text() in checked_user_list) and (qBox.isChecked() is False):
                self.log_tab_user_combo.checkBoxList[i].setChecked(True)

    def get_log_user_list(self):
        """
        Get user list under log dir, only return CURRENT_USER with no-root account.
        """
        log_user_list = []
        log_dir = str(config.db_path) + '/log'

        for dir_name in os.listdir(log_dir):
            dir_path = os.path.join(log_dir, dir_name)
            command_his_file = str(dir_path) + '/command.his'

            if os.path.isdir(dir_path) and os.path.exists(command_his_file):
                log_user_list.append(dir_name)

        if CURRENT_USER == 'root':
            return log_user_list
        else:
            if CURRENT_USER in log_user_list:
                return [CURRENT_USER]
            else:
                return []

    def gen_log_tab_table(self):
        """
        Generate self.log_tab_tale.
        """
        self.collect_log_tab_table_info()

        # self.log_tab_table
        self.log_tab_table.setShowGrid(True)
        self.log_tab_table.setSortingEnabled(True)
        self.log_tab_table.setColumnCount(0)
        self.log_tab_table.setColumnCount(5)
        self.log_tab_table_title_list = ['Time', 'User', 'Login_User', 'Command', 'Log']
        self.log_tab_table.setHorizontalHeaderLabels(self.log_tab_table_title_list)

        self.log_tab_table.setColumnWidth(0, 155)
        self.log_tab_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.log_tab_table.setColumnWidth(4, 40)

        # Fill self.log_tab_table items.
        self.log_tab_table.setRowCount(0)
        self.log_tab_table.setRowCount(len(self.log_dic_list))

        i = -1

        for log_dic in self.log_dic_list:
            i += 1

            # Fill "Time" item.
            j = 0
            item = QTableWidgetItem(log_dic['time'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "User" item.
            j += 1
            item = QTableWidgetItem(log_dic['user'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "Login_User" item.
            j += 1
            item = QTableWidgetItem(log_dic['login_user'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "Command" item.
            j += 1
            item = QTableWidgetItem(log_dic['command'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "Log" item.
            j += 1
            item = QTableWidgetItem()
            item.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/log.png'))
            self.log_tab_table.setItem(i, j, item)

    def collect_log_tab_table_info(self):
        """
        Collect history records with specified user/begin_date/end_date.
        """
        self.log_dic_list = []
        specified_user_list = self.log_tab_user_combo.currentText().strip().split()
        specified_begin_date = self.log_tab_begin_date_edit.date().toString('yyyyMMdd')
        specified_end_date = self.log_tab_end_date_edit.date().toString('yyyyMMdd')
        specified_info = self.log_tab_info_line.text().strip()

        if 'ALL' in specified_user_list:
            specified_user_list = self.get_log_user_list()

        for specified_user in specified_user_list:
            user_command_history_file = str(config.db_path) + '/log/' + str(specified_user) + '/command.his'

            with open(user_command_history_file, 'r') as UCHF:
                lines = UCHF.readlines()
                lines.reverse()

                for line in lines:
                    line_dic = json.loads(line)

                    if specified_begin_date <= line_dic['date'] <= specified_end_date:
                        if (not specified_info) or re.search(specified_info, line_dic['command']):
                            time = datetime.datetime.strptime(str(line_dic['date']) + str(line_dic['time']), '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
                            self.log_dic_list.insert(0, {'time': time, 'user': line_dic['user'], 'login_user': line_dic['login_user'], 'command': line_dic['command'], 'log': line_dic['log']})

        return self.log_dic_list

    def gen_log_tab_frame1(self):
        # self.log_tab_frame1
        self.log_tab_log_text = QTextEdit(self.log_tab_frame1)

        # self.log_tab_frame1 - Grid
        log_tab_frame1_grid = QGridLayout()
        log_tab_frame1_grid.addWidget(self.log_tab_log_text, 0, 0)
        self.log_tab_frame1.setLayout(log_tab_frame1_grid)

    def update_log_tab_frame1(self, message):
        """
        self.update self.log_tab_log_text with specified message.
        """
        self.log_tab_log_text.clear()
        self.log_tab_log_text.insertPlainText(message)
        common_pyqt5.text_edit_visible_position(self.log_tab_log_text, 'Start')
# For log TAB (end) #

# Export table (start) #
    def export_group_table(self):
        self.export_table('group', self.group_tab_table, self.group_tab_table_title_list)

    def export_host_table(self):
        self.export_table('host', self.host_tab_table, self.host_tab_table_title_list)

    def export_run_table(self):
        self.export_table('run', self.run_tab_table, self.run_tab_table_title_list)

    def export_log_table(self):
        self.export_table('log', self.log_tab_table, self.log_tab_table_title_list)

    def export_table(self, table_type, table_item, title_list):
        """
        Export specified table info into an csv file.
        """
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        current_time_string = re.sub('-', '', current_time)
        current_time_string = re.sub(':', '', current_time_string)
        current_time_string = re.sub(' ', '_', current_time_string)
        default_output_file = './batchRun_' + str(table_type) + '_' + str(current_time_string) + '.csv'
        (output_file, output_file_type) = QFileDialog.getSaveFileName(self, 'Export ' + str(table_type) + ' table', default_output_file, 'CSV Files (*.csv)')

        if output_file:
            # Get table content.
            content_dic = {}
            row_num = table_item.rowCount()
            column_num = table_item.columnCount()

            for column in range(column_num):
                column_list = []

                for row in range(row_num):
                    if table_item.item(row, column):
                        column_list.append(table_item.item(row, column).text())
                    else:
                        column_list.append('')

                content_dic.setdefault(title_list[column], column_list)

            # Write csv
            common.bprint('Writing ' + str(table_type) + ' table into "' + str(output_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')
            common.write_csv(csv_file=output_file, content_dic=content_dic)
# Export table (end) #

    def closeEvent(self, QCloseEvent):
        """
        When window close, post-process.
        """
        common.bprint('Bye', date_format='%Y-%m-%d %H:%M:%S')
        self.xterm_widget.close()


class XtermWidget(QWidget):
    def __init__(self, parent=None):
        super(XtermWidget, self).__init__(parent)
        self.process = QProcess(self)
        layout = QGridLayout()
        self.setLayout(layout)
        self.cmd = f'xterm -bg black -fg white -into {str(int(self.winId()))} -geometry 200x200 -sb -l -lc -lf /dev/stdout -e /bin/bash -c "ps -o tt=;bash" | tee'
        self.process.start(self.cmd)

    def resizeEvent(self, event):
        super(XtermWidget, self).resizeEvent(event)
        self.updateTerminalSize()

    def updateTerminalSize(self):
        if self.process.state() == QProcess.Running:
            self.process.terminate()
            self.process.waitForFinished()

            if self.process.state() == QProcess.Running:
                self.process.kill()
                self.process.waitForFinished()

        if self.process.state() == QProcess.NotRunning:
            self.process.start(self.cmd)

    def closeEvent(self, a0):
        super(XtermWidget, self).closeEvent(a0)

        if self.process is not None:
            self.process.terminate()
            self.process.waitForFinished(3000)

            if self.process.state() == QProcess.Running:
                self.process.kill()
                self.process.waitForFinished()


class ShowMessage(QThread):
    """
    Show message with tool message.
    """
    def __init__(self, title, message):
        super(ShowMessage, self).__init__()
        self.title = title
        self.message = message

    def run(self):
        command = 'python3 ' + str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/tools/message.py --title "' + str(self.title) + '" --message "' + str(self.message) + '"'
        os.system(command)


################
# Main Process #
################
def main():
    app = QApplication(sys.argv)
    mw = MainWindow()
    mw.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
