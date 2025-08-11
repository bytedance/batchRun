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
import time
import getpass
import datetime
import qdarkstyle

from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QAction, qApp, QTabWidget, QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QMessageBox, QLineEdit, QHeaderView, QFileDialog, QTextEdit, QTreeWidget, QTreeWidgetItem, QDateEdit, QSplitter, QComboBox, QMenu, QSizePolicy
from PyQt5.QtGui import QIcon, QBrush, QFont, QColor
from PyQt5.QtCore import Qt, QThread, QProcess, QDate

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common
import common_pyqt5

os.environ['PYTHONUNBUFFERED'] = '1'
CURRENT_USER = getpass.getuser()
VERSION = 'V2.2'
VERSION_DATE = '2025.04.27'


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
        # self.host_list_class: group/host_ip/host_name/ssh_port relationship from host.list.
        self.host_list_class = common.ParseHostList()

        # self.completer_host_list: completer for Host.
        # self.host_group_relationship_dic: host -> group.
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

        # self.network_scan_dic: get zone/network/ip relationship from network_scan.json.
        self.network_scan_dic = {}
        network_scan_file = str(config.db_path) + '/network_scan/network_scan.json'

        if not os.path.exists(network_scan_file):
            common.bprint('Network scan file "' + str(network_scan_file) + '" is missing.', date_format='%Y-%m-%d %H:%M:%S', level='Warning')
        else:
            common.bprint('Loading network scan file "' + str(network_scan_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')

            with open(network_scan_file, 'r') as NSF:
                self.network_scan_dic = json.loads(NSF.read())

        # self.host_asset_dic: get asset information.
        self.host_asset_dic = {}
        host_asset_file = str(config.db_path) + '/host_asset/host_asset.json'

        if not os.path.exists(host_asset_file):
            common.bprint('Host asset file "' + str(host_asset_file) + '" is missing.', date_format='%Y-%m-%d %H:%M:%S', level='Warning')
        else:
            common.bprint('Loading host asset file "' + str(host_asset_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')

            with open(host_asset_file, 'r') as HAF:
                self.host_asset_dic = json.loads(HAF.read())

        # self.host_queue_dic: get host scheduler/cluster/queue information from host_queue.json.
        self.host_queue_dic = {}
        host_queue_file = str(config.db_path) + '/host_queue/host_queue.json'

        if not os.path.exists(host_queue_file):
            common.bprint('Host queue file "' + str(host_queue_file) + '" is missing.', date_format='%Y-%m-%d %H:%M:%S', level='Warning')
        else:
            common.bprint('Loading host queue file "' + str(host_queue_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')

            with open(host_queue_file, 'r') as HQF:
                self.host_queue_dic = json.loads(HQF.read())

        # self.scheduler_cluster_queue_dic: get scheduler -> cluster -> queue relationship from self.host_queue_dic.
        common.bprint('Collecting host scheduler/cluster/queue relationship ...', date_format='%Y-%m-%d %H:%M:%S')
        self.scheduler_cluster_queue_dic = {}

        for host_ip in self.host_queue_dic.keys():
            if self.host_queue_dic[host_ip]:
                if ('scheduler' in self.host_queue_dic[host_ip]) and ('cluster' in self.host_queue_dic[host_ip]) and ('queues' in self.host_queue_dic[host_ip]):
                    scheduler = self.host_queue_dic[host_ip]['scheduler']
                    cluster = self.host_queue_dic[host_ip]['cluster']
                    queue_list = self.host_queue_dic[host_ip]['queues']

                    self.scheduler_cluster_queue_dic.setdefault(scheduler, {})
                    self.scheduler_cluster_queue_dic[scheduler].setdefault(cluster, [])
                    self.scheduler_cluster_queue_dic[scheduler][cluster].extend(queue_list)

        # self.host_info_dic: get host static information from host_info.json.
        self.host_info_dic = {}
        host_info_file = str(config.db_path) + '/host_info/host_info.json'

        if not os.path.exists(host_info_file):
            common.bprint('Host info file "' + str(host_info_file) + '" is missing.', date_format='%Y-%m-%d %H:%M:%S', level='Warning')
        else:
            common.bprint('Loading host info file "' + str(host_info_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')

            with open(host_info_file, 'r') as HIF:
                self.host_info_dic = json.loads(HIF.read())

        # self.run_tab_table_dic: get selected host_ip(s)/host_name(s) from GROUP or HOST tab.
        self.run_tab_table_dic = {}

        for group in self.host_list_class.expanded_host_list_dic.keys():
            if (('RUN' in self.host_list_class.expanded_host_list_dic) and (group == 'RUN')) or ('RUN' not in self.host_list_class.expanded_host_list_dic):
                for host_ip in self.host_list_class.expanded_host_list_dic[group].keys():
                    if host_ip not in self.run_tab_table_dic.keys():
                        host_name = '  '.join(self.host_list_class.expanded_host_list_dic[group][host_ip]['host_name'])

                        if host_ip in self.host_group_relationship_dic.keys():
                            groups = '  '.join(self.host_group_relationship_dic[host_ip])
                        else:
                            groups = group

                        self.run_tab_table_dic[host_ip] = {'hidden': False, 'state': Qt.Checked, 'host_name': host_name, 'groups': groups, 'output_message': ''}

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
        self.scan_tab = QWidget()
        self.asset_tab = QWidget()
        self.host_tab = QWidget()
        self.stat_tab = QWidget()
        self.run_tab = QWidget()
        self.log_tab = QWidget()

        # Add the sub-tabs into main Tab widget
        if self.network_scan_dic:
            self.main_tab.addTab(self.scan_tab, 'SCAN')

        if self.host_asset_dic:
            self.main_tab.addTab(self.asset_tab, 'ASSET')

        self.main_tab.addTab(self.host_tab, 'HOST')
        self.main_tab.addTab(self.stat_tab, 'STAT')
        self.main_tab.addTab(self.run_tab, 'RUN')
        self.main_tab.addTab(self.log_tab, 'LOG')

        # Generate the sub-tabs
        if self.network_scan_dic:
            self.gen_scan_tab()

        if self.host_asset_dic:
            self.gen_asset_tab()

        self.gen_host_tab()
        self.gen_stat_tab()
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
        export_scan_table_action = QAction('Export scan table', self)
        export_scan_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_scan_table_action.triggered.connect(self.export_scan_table)

        export_asset_table_action = QAction('Export asset table', self)
        export_asset_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_asset_table_action.triggered.connect(self.export_asset_table)

        export_host_table_action = QAction('Export host table', self)
        export_host_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_host_table_action.triggered.connect(self.export_host_table)

        export_stat_table_action = QAction('Export stat table', self)
        export_stat_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_stat_table_action.triggered.connect(self.export_stat_table)

        export_run_table_action = QAction('Export run table', self)
        export_run_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_run_table_action.triggered.connect(self.export_run_table)

        export_log_table_action = QAction('Export log table', self)
        export_log_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_log_table_action.triggered.connect(self.export_log_table)

        import_run_list_action = QAction('Import run list', self)
        import_run_list_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/load.png'))
        import_run_list_action.triggered.connect(self.import_run_list)

        exit_action = QAction('Exit', self)
        exit_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/exit.png'))
        exit_action.triggered.connect(qApp.quit)

        file_menu = menubar.addMenu('File')

        if self.network_scan_dic:
            file_menu.addAction(export_scan_table_action)

        if self.host_asset_dic:
            file_menu.addAction(export_asset_table_action)

        file_menu.addAction(export_host_table_action)
        file_menu.addAction(export_stat_table_action)
        file_menu.addAction(export_run_table_action)
        file_menu.addAction(export_log_table_action)
        file_menu.addAction(import_run_list_action)
        file_menu.addAction(exit_action)

        # Function
        switch_etc_hosts_action = QAction('Switch etc hosts', self)
        switch_etc_hosts_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/switch.png'))
        switch_etc_hosts_action.triggered.connect(self.switch_etc_hosts)

        network_scan_action = QAction('Network scan', self)
        network_scan_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/radar.png'))
        network_scan_action.triggered.connect(self.network_scan)

        sample_host_info_action = QAction('Sample host info', self)
        sample_host_info_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/database.png'))
        sample_host_info_action.triggered.connect(self.sample_host_info)

        sample_host_queue_action = QAction('Sample host queue', self)
        sample_host_queue_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/database.png'))
        sample_host_queue_action.triggered.connect(self.sample_host_queue)

        sample_host_stat_action = QAction('Sample host stat', self)
        sample_host_stat_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/database.png'))
        sample_host_stat_action.triggered.connect(self.sample_host_stat)

        function_menu = menubar.addMenu('Function')
        function_menu.addAction(switch_etc_hosts_action)

        if self.network_scan_dic:
            function_menu.addAction(network_scan_action)

        function_menu.addAction(sample_host_info_action)
        function_menu.addAction(sample_host_queue_action)
        function_menu.addAction(sample_host_stat_action)

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

    def switch_etc_hosts(self):
        """
        Call the tools/switch_cetc_hosts tool to convert the hosts file to the host.list file of batchRun.
        """
        if config.switch_etc_hosts_command:
            my_show_message = ShowMessage('Info', 'Switching etc hosts ...')
            my_show_message.start()
            os.system(config.switch_etc_hosts_command)
            self.init_var()
            self.gen_host_tab()
            self.gen_run_tab()
            my_show_message.terminate()

    def network_scan(self):
        """
        Call the tools/network_scan tool to scan specified network.
        """
        if config.network_scan_command:
            my_show_message = ShowMessage('Info', 'Scaning network ...')
            my_show_message.start()
            os.system(config.network_scan_command)
            self.init_var()
            self.gen_scan_tab()
            my_show_message.terminate()

    def sample_host_info(self):
        """
        Call the tools/sample_host_info tool to sample host information.
        """
        if config.sample_host_info_command:
            my_show_message = ShowMessage('Info', 'Sampling host info ...')
            my_show_message.start()
            os.system(config.sample_host_info_command)
            self.init_var()
            self.gen_host_tab()
            my_show_message.terminate()

    def sample_host_queue(self):
        """
        Call the tools/sample_host_queue tool to sample scheduler/cluster/queue information.
        """
        if config.sample_host_queue_command:
            my_show_message = ShowMessage('Info', 'Sampling host queue info ...')
            my_show_message.start()
            os.system(config.sample_host_queue_command)
            self.init_var()
            my_show_message.terminate()

    def sample_host_stat(self):
        """
        Call the tools/sample_host_stat tool to sample host stat information.
        """
        if config.sample_host_stat_command:
            my_show_message = ShowMessage('Info', 'Sampling host stat info ...')
            my_show_message.start()
            os.system(config.sample_host_stat_command)
            self.init_var()
            self.gen_stat_tab()
            my_show_message.terminate()

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

# Common sub-functions (begin) #
    def gui_warning(self, warning_message):
        """
        Show the specified warning message on both of command line and GUI window.
        """
        common.bprint(warning_message, date_format='%Y-%m-%d %H:%M:%S', level='Warning')
        QMessageBox.warning(self, 'batchRun Warning', warning_message)
# Common sub-functions (end) #

# For scan TAB (begin) #
    def gen_scan_tab(self):
        """
        Generate the SCAN tab on batchRun GUI, show network_scan.json and host.list informations.
        """
        if not self.scan_tab.layout():
            # self.scan_tab
            self.scan_tab_qtree = QTreeWidget(self.scan_tab)
            self.scan_tab_qtree.itemDoubleClicked.connect(self.scan_tab_qtree_double_clicked)

            self.scan_tab_frame0 = QFrame(self.scan_tab)
            self.scan_tab_frame0.setFrameShadow(QFrame.Raised)
            self.scan_tab_frame0.setFrameShape(QFrame.Box)

            self.scan_tab_table = QTableWidget(self.scan_tab)

            # self.scan_tab - Grid
            scan_tab_grid = QGridLayout()

            scan_tab_grid.addWidget(self.scan_tab_qtree, 0, 0, 2, 1)
            scan_tab_grid.addWidget(self.scan_tab_frame0, 0, 1)
            scan_tab_grid.addWidget(self.scan_tab_table, 1, 1)

            scan_tab_grid.setRowStretch(0, 1)
            scan_tab_grid.setRowStretch(1, 20)

            scan_tab_grid.setColumnStretch(0, 1)
            scan_tab_grid.setColumnStretch(1, 5)

            self.scan_tab.setLayout(scan_tab_grid)

        # Generate sub-frames
        self.gen_scan_tab_qtree()
        self.gen_scan_tab_frame0()
        self.gen_scan_tab_table()

    def gen_scan_tab_qtree(self):
        # self.scan_tab_qtree
        self.scan_tab_qtree.setColumnCount(1)
        self.scan_tab_qtree.setHeaderLabels(['     Zone  -  Network  - Ip', ])
        self.scan_tab_qtree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.scan_tab_qtree.header().setStretchLastSection(False)

        zone_list = list(self.network_scan_dic.keys())

        # Add items.
        for zone in zone_list:
            zone_item = QTreeWidgetItem(self.scan_tab_qtree)
            zone_item.setText(0, zone)
            zone_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/Z.png'))

            for network in self.network_scan_dic[zone].keys():
                child_item = QTreeWidgetItem()
                child_item.setText(0, network)
                child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/N.png'))

                for host_ip in self.network_scan_dic[zone][network].keys():
                    sub_child_item = QTreeWidgetItem()
                    sub_child_item.setText(0, host_ip)
                    sub_child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/H.png'))
                    child_item.addChild(sub_child_item)

                zone_item.addChild(child_item)

            self.scan_tab_qtree.expandItem(zone_item)

    def scan_tab_qtree_double_clicked(self, item, column):
        """
        Select double clicked zone/network on self.scan_tab_frame0.
        """
        item_text = item.text(column)
        self.scan_tab_host_line.setText('')

        for (i, qBox) in enumerate(self.scan_tab_zone_combo.checkBoxList):
            if qBox.text() == 'ALL':
                self.scan_tab_zone_combo.checkBoxList[i].setChecked(True)
            else:
                self.scan_tab_zone_combo.checkBoxList[i].setChecked(False)

        for (i, qBox) in enumerate(self.scan_tab_network_combo.checkBoxList):
            if qBox.text() == 'ALL':
                self.scan_tab_network_combo.checkBoxList[i].setChecked(True)
            else:
                self.scan_tab_network_combo.checkBoxList[i].setChecked(False)

        if item_text:
            zone_list = []
            network_list = []

            for zone in self.network_scan_dic.keys():
                zone_list = zone_list + [zone] if zone not in zone_list else zone_list

                for network in self.network_scan_dic[zone].keys():
                    network_list = network_list + [network] if network not in network_list else network_list

            if item_text in zone_list:
                for (i, qBox) in enumerate(self.scan_tab_zone_combo.checkBoxList):
                    if qBox.text() == item_text:
                        self.scan_tab_zone_combo.checkBoxList[i].setChecked(True)
            elif item_text in network_list:
                for (i, qBox) in enumerate(self.scan_tab_network_combo.checkBoxList):
                    if qBox.text() == item_text:
                        self.scan_tab_network_combo.checkBoxList[i].setChecked(True)
            else:
                self.scan_tab_host_line.setText(item_text)

            self.gen_scan_tab_table()

    def gen_scan_tab_frame0(self):
        # self.scan_tab_frame0
        if self.scan_tab_frame0.layout():
            self.set_scan_tab_zone_combo()
            self.set_scan_tab_network_combo()
            return

        # "Zone" item.
        scan_tab_zone_label = QLabel('Zone', self.scan_tab_frame0)
        scan_tab_zone_label.setStyleSheet("font-weight: bold;")
        scan_tab_zone_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.scan_tab_zone_combo = common_pyqt5.QComboCheckBox(self.scan_tab_frame0)
        self.set_scan_tab_zone_combo()
        self.scan_tab_zone_combo.activated.connect(lambda: self.set_scan_tab_network_combo())

        # "Network" item.
        scan_tab_network_label = QLabel('Network', self.scan_tab_frame0)
        scan_tab_network_label.setStyleSheet("font-weight: bold;")
        scan_tab_network_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.scan_tab_network_combo = common_pyqt5.QComboCheckBox(self.scan_tab_frame0)
        self.set_scan_tab_network_combo()

        # "Host" item.
        scan_tab_host_label = QLabel('Host', self.scan_tab_frame0)
        scan_tab_host_label.setStyleSheet("font-weight: bold;")
        scan_tab_host_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.scan_tab_host_line = QLineEdit()
        self.scan_tab_host_line.returnPressed.connect(self.gen_scan_tab_table)

        scan_tab_host_line_completer = common_pyqt5.get_completer(self.completer_host_list)
        self.scan_tab_host_line.setCompleter(scan_tab_host_line_completer)

        # empty item.
        scan_tab_empty_label = QLabel('', self.scan_tab_frame0)

        # "Check" button.
        scan_tab_check_button = QPushButton('Check', self.scan_tab_frame0)
        scan_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        scan_tab_check_button.clicked.connect(self.gen_scan_tab_table)

        # self.scan_tab_frame0 - Grid
        scan_tab_frame0_grid = QGridLayout()

        scan_tab_frame0_grid.addWidget(scan_tab_zone_label, 0, 0)
        scan_tab_frame0_grid.addWidget(self.scan_tab_zone_combo, 0, 1)
        scan_tab_frame0_grid.addWidget(scan_tab_network_label, 0, 2)
        scan_tab_frame0_grid.addWidget(self.scan_tab_network_combo, 0, 3)
        scan_tab_frame0_grid.addWidget(scan_tab_host_label, 0, 4)
        scan_tab_frame0_grid.addWidget(self.scan_tab_host_line, 0, 5)
        scan_tab_frame0_grid.addWidget(scan_tab_empty_label, 0, 6)
        scan_tab_frame0_grid.addWidget(scan_tab_check_button, 0, 7)

        scan_tab_frame0_grid.setColumnStretch(0, 2)
        scan_tab_frame0_grid.setColumnStretch(1, 2)
        scan_tab_frame0_grid.setColumnStretch(2, 2)
        scan_tab_frame0_grid.setColumnStretch(3, 2)
        scan_tab_frame0_grid.setColumnStretch(4, 2)
        scan_tab_frame0_grid.setColumnStretch(5, 12)
        scan_tab_frame0_grid.setColumnStretch(6, 1)
        scan_tab_frame0_grid.setColumnStretch(7, 2)

        self.scan_tab_frame0.setLayout(scan_tab_frame0_grid)

    def set_scan_tab_zone_combo(self, checked_zone_list=['ALL', ]):
        """
        Set (initialize) self.scan_tab_zone_combo.
        """
        self.scan_tab_zone_combo.clear()

        zone_list = copy.deepcopy(list(self.network_scan_dic.keys()))
        zone_list.sort()
        zone_list.insert(0, 'ALL')

        for zone in zone_list:
            self.scan_tab_zone_combo.addCheckBoxItem(zone, update_width=True)

        # Set to checked status for checked_zone_list.
        for (i, qBox) in enumerate(self.scan_tab_zone_combo.checkBoxList):
            if (qBox.text() in checked_zone_list) and (qBox.isChecked() is False):
                self.scan_tab_zone_combo.checkBoxList[i].setChecked(True)

    def set_scan_tab_network_combo(self, checked_network_list=['ALL', ]):
        """
        Set (initialize) self.scan_tab_network_combo.
        """
        self.scan_tab_network_combo.clear()

        specified_zone_list = self.scan_tab_zone_combo.currentText().strip().split()
        network_list = []

        for zone in self.network_scan_dic.keys():
            if ('ALL' in specified_zone_list) or (zone in specified_zone_list):
                for network in self.network_scan_dic[zone].keys():
                    if network not in network_list:
                        network_list.append(network)

        network_list.sort()
        network_list.insert(0, 'ALL')

        for network in network_list:
            self.scan_tab_network_combo.addCheckBoxItem(network, update_width=True)

        # Set to checked status for checked_network_list.
        for (i, qBox) in enumerate(self.scan_tab_network_combo.checkBoxList):
            if (qBox.text() in checked_network_list) and (qBox.isChecked() is False):
                self.scan_tab_network_combo.checkBoxList[i].setChecked(True)

    def gen_scan_tab_table(self):
        scan_tab_table_dic = self.collect_scan_tab_table_info()

        # self.scan_tab_table
        self.scan_tab_table.setShowGrid(True)
        self.scan_tab_table.setSortingEnabled(True)
        self.scan_tab_table.setColumnCount(0)
        self.scan_tab_table_title_list = ['zone', 'network', 'host_ip', 'host_name', 'groups', 'packet', 'received', 'packet_loss', 'rtt_avg']
        self.scan_tab_table.setColumnCount(len(self.scan_tab_table_title_list))
        self.scan_tab_table.setHorizontalHeaderLabels(self.scan_tab_table_title_list)

        self.scan_tab_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_tab_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.scan_tab_table.setColumnWidth(2, 120)
        self.scan_tab_table.setColumnWidth(3, 160)
        self.scan_tab_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.scan_tab_table.setColumnWidth(5, 80)
        self.scan_tab_table.setColumnWidth(6, 80)
        self.scan_tab_table.setColumnWidth(7, 120)
        self.scan_tab_table.setColumnWidth(8, 100)

        # Fill self.scan_tab_table items.
        host_line_num = 0

        for zone in scan_tab_table_dic.keys():
            for network in scan_tab_table_dic[zone].keys():
                for host_ip in scan_tab_table_dic[zone][network].keys():
                    host_line_num += 1

        self.scan_tab_table.setRowCount(0)
        self.scan_tab_table.setRowCount(host_line_num)

        i = -1

        for zone in scan_tab_table_dic.keys():
            for network in scan_tab_table_dic[zone].keys():
                for host_ip in scan_tab_table_dic[zone][network].keys():
                    i += 1
                    host_name = scan_tab_table_dic[zone][network][host_ip]['host_name']
                    groups = scan_tab_table_dic[zone][network][host_ip]['groups']
                    packet = scan_tab_table_dic[zone][network][host_ip]['packet']
                    received = scan_tab_table_dic[zone][network][host_ip]['received']
                    packet_loss = scan_tab_table_dic[zone][network][host_ip]['packet_loss']
                    rtt_avg = str(scan_tab_table_dic[zone][network][host_ip]['rtt_avg']) + ' ' + str(scan_tab_table_dic[zone][network][host_ip]['rtt_unit'])

                    # Fill "zone" item.
                    j = 0
                    item = QTableWidgetItem(zone)
                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "network" item.
                    j += 1
                    item = QTableWidgetItem(network)
                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "host_ip" item.
                    j += 1
                    item = QTableWidgetItem(host_ip)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "host_name" item.
                    j += 1
                    item = QTableWidgetItem(host_name)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "groups" item.
                    j += 1
                    item = QTableWidgetItem(groups)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "packet" item.
                    j += 1
                    item = QTableWidgetItem()
                    item.setData(Qt.DisplayRole, packet)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "received" item.
                    j += 1
                    item = QTableWidgetItem()
                    item.setData(Qt.DisplayRole, received)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "packet_loss" item.
                    j += 1
                    item = QTableWidgetItem(packet_loss)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

                    # Fill "rtt_avg" item.
                    j += 1
                    item = QTableWidgetItem(rtt_avg)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.scan_tab_table.setItem(i, j, item)

    def collect_scan_tab_table_info(self):
        """
        Collect host info with specified zone/network/host.
        scan_tab_table_dic = {zone: {network: {host_ip: {***}}},
                             }
        """
        scan_tab_table_dic = {}
        specified_zone_list = self.scan_tab_zone_combo.currentText().strip().split()
        specified_network_list = self.scan_tab_network_combo.currentText().strip().split()
        specified_host_list = self.scan_tab_host_line.text().strip().split()

        if specified_zone_list and specified_network_list:
            for zone in self.network_scan_dic.keys():
                if ('ALL' in specified_zone_list) or (zone in specified_zone_list):
                    scan_tab_table_dic.setdefault(zone, {})

                    for network in self.network_scan_dic[zone].keys():
                        if ('ALL' in specified_network_list) or (network in specified_network_list):
                            scan_tab_table_dic[zone].setdefault(network, {})

                            for host_ip in self.network_scan_dic[zone][network].keys():
                                if (not specified_host_list) or (host_ip in specified_host_list) or ((host_ip in self.host_list_class.host_ip_dic) and any(host_name in specified_host_list for host_name in self.host_list_class.host_ip_dic[host_ip]['host_name'])):
                                    scan_tab_table_dic[zone][network][host_ip] = self.network_scan_dic[zone][network][host_ip]

                                    if host_ip in self.host_list_class.host_ip_dic.keys():
                                        scan_tab_table_dic[zone][network][host_ip]['host_name'] = '  '.join(self.host_list_class.host_ip_dic[host_ip]['host_name'])

                                        if host_ip in self.host_group_relationship_dic.keys():
                                            scan_tab_table_dic[zone][network][host_ip]['groups'] = '  '.join(self.host_group_relationship_dic[host_ip])
                                        else:
                                            scan_tab_table_dic[zone][network][host_ip]['groups'] = ''
                                    else:
                                        scan_tab_table_dic[zone][network][host_ip]['host_name'] = ''
                                        scan_tab_table_dic[zone][network][host_ip]['groups'] = ''

        return scan_tab_table_dic
# For scan TAB (end) #

# For asset TAB (begin) #
    def gen_asset_tab(self):
        """
        Generate the ASSET tab on batchRun GUI, show host_asset.json informations.
        """
        if not self.asset_tab.layout():
            # self.asset_tab
            self.asset_tab_frame0 = QFrame(self.asset_tab)
            self.asset_tab_frame0.setFrameShadow(QFrame.Raised)
            self.asset_tab_frame0.setFrameShape(QFrame.Box)

            self.asset_tab_table = QTableWidget(self.asset_tab)

            # self.asset_tab - Grid
            asset_tab_grid = QGridLayout()

            asset_tab_grid.addWidget(self.asset_tab_frame0, 0, 0)
            asset_tab_grid.addWidget(self.asset_tab_table, 1, 0)

            asset_tab_grid.setRowStretch(0, 1)
            asset_tab_grid.setRowStretch(1, 20)

            self.asset_tab.setLayout(asset_tab_grid)

        # Generate sub-frames
        self.gen_asset_tab_frame0()
        self.gen_asset_tab_table()

    def gen_asset_tab_frame0(self):
        # self.asset_tab_frame0
        if self.asset_tab_frame0.layout():
            return

        # "Select" item.
        asset_tab_select_label = QLabel('Select', self.asset_tab_frame0)
        asset_tab_select_label.setStyleSheet("font-weight: bold;")
        asset_tab_select_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.asset_tab_select_line = QLineEdit()
        self.asset_tab_select_line.returnPressed.connect(self.gen_asset_tab_table)

        # empty item.
        asset_tab_empty_label = QLabel('', self.asset_tab_frame0)

        # "Check" button.
        asset_tab_check_button = QPushButton('Check', self.asset_tab_frame0)
        asset_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        asset_tab_check_button.clicked.connect(self.gen_asset_tab_table)

        # "toHost" button.
        asset_tab_tohost_button = QPushButton('toHost', self.asset_tab_frame0)
        asset_tab_tohost_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        asset_tab_tohost_button.clicked.connect(self.asset_to_host_tab)

        # "toStat" button.
        asset_tab_tostat_button = QPushButton('toStat', self.asset_tab_frame0)
        asset_tab_tostat_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        asset_tab_tostat_button.clicked.connect(self.asset_to_stat_tab)

        # "toRun" button.
        asset_tab_torun_button = QPushButton('toRun', self.asset_tab_frame0)
        asset_tab_torun_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        asset_tab_torun_button.clicked.connect(self.asset_to_run_tab)

        # self.asset_tab_frame0 - Grid
        asset_tab_frame0_grid = QGridLayout()

        asset_tab_frame0_grid.addWidget(asset_tab_select_label, 0, 0)
        asset_tab_frame0_grid.addWidget(self.asset_tab_select_line, 0, 1)
        asset_tab_frame0_grid.addWidget(asset_tab_empty_label, 0, 2)
        asset_tab_frame0_grid.addWidget(asset_tab_check_button, 0, 3)
        asset_tab_frame0_grid.addWidget(asset_tab_tohost_button, 0, 4)
        asset_tab_frame0_grid.addWidget(asset_tab_tostat_button, 0, 5)
        asset_tab_frame0_grid.addWidget(asset_tab_torun_button, 0, 6)

        asset_tab_frame0_grid.setColumnStretch(0, 2)
        asset_tab_frame0_grid.setColumnStretch(1, 18)
        asset_tab_frame0_grid.setColumnStretch(2, 1)
        asset_tab_frame0_grid.setColumnStretch(3, 2)
        asset_tab_frame0_grid.setColumnStretch(4, 2)
        asset_tab_frame0_grid.setColumnStretch(5, 2)
        asset_tab_frame0_grid.setColumnStretch(6, 2)

        self.asset_tab_frame0.setLayout(asset_tab_frame0_grid)

    def gen_asset_tab_table(self, specified_host_ip_list=[]):
        orig_asset_tab_table_dic = self.collect_asset_tab_table_info()

        if not specified_host_ip_list:
            asset_tab_table_dic = orig_asset_tab_table_dic
        else:
            asset_tab_table_dic = {}

            for specified_host_ip in specified_host_ip_list:
                if specified_host_ip in orig_asset_tab_table_dic.keys():
                    asset_tab_table_dic[specified_host_ip] = orig_asset_tab_table_dic[specified_host_ip]

        # self.asset_tab_table
        self.asset_tab_table.setShowGrid(True)
        self.asset_tab_table.setSortingEnabled(True)
        self.asset_tab_table.setColumnCount(0)

        if asset_tab_table_dic:
            first_asset_host_ip = list(asset_tab_table_dic.keys())[0]
            self.asset_tab_table_title_list = list(asset_tab_table_dic[first_asset_host_ip].keys())
            self.asset_tab_table_title_list.insert(0, 'host_ip')
            self.asset_tab_table_title_list.insert(1, 'host_name')
            self.asset_tab_table_title_list.insert(2, 'groups')
        else:
            self.asset_tab_table_title_list = ['host_ip', 'host_name', 'groups']

        self.asset_tab_table.setColumnCount(len(self.asset_tab_table_title_list))
        self.asset_tab_table.setHorizontalHeaderLabels(self.asset_tab_table_title_list)

        # Fill self.asset_tab_table items.
        self.asset_tab_table.setRowCount(0)
        self.asset_tab_table.setRowCount(len(asset_tab_table_dic))

        i = -1

        for host_ip in asset_tab_table_dic.keys():
            i += 1

            # Fill "host_ip" item.
            j = 0
            item = QTableWidgetItem(host_ip)
            self.asset_tab_table.setItem(i, j, item)

            # Fill "host_name" item.
            j += 1
            item = QTableWidgetItem(asset_tab_table_dic[host_ip]['host_name'])

            if not asset_tab_table_dic[host_ip]['host_name']:
                item.setBackground(QBrush(Qt.red))

            self.asset_tab_table.setItem(i, j, item)

            # Fill "group" item.
            j += 1
            item = QTableWidgetItem(asset_tab_table_dic[host_ip]['groups'])

            if not asset_tab_table_dic[host_ip]['groups']:
                item.setBackground(QBrush(Qt.red))

            self.asset_tab_table.setItem(i, j, item)

            # Fill other items.
            for host_ip_attribute in asset_tab_table_dic[host_ip].keys():
                j += 1
                item_string = asset_tab_table_dic[host_ip][host_ip_attribute]

                if isinstance(item_string, list):
                    item_string = '  '.join(item_string)

                item = QTableWidgetItem(item_string)
                self.asset_tab_table.setItem(i, j, item)

        self.asset_tab_table.resizeColumnsToContents()
        header = self.asset_tab_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

    def collect_asset_tab_table_info(self):
        """
        Collect host asset info with specified select condition.
        """
        asset_tab_table_dic = {}
        host_asset_file = str(config.db_path) + '/host_asset/host_asset.json'
        host_asset_dic = self.get_asset_info(host_asset_file)
        select_string = self.asset_tab_select_line.text().strip()

        if not select_string:
            asset_tab_table_dic = host_asset_dic
        else:
            for host_ip in host_asset_dic.keys():
                try:
                    if eval(select_string, {}, host_asset_dic[host_ip]):
                        asset_tab_table_dic[host_ip] = host_asset_dic[host_ip]
                except Exception:
                    asset_tab_table_dic = host_asset_dic
                    warning_message = 'Invalid select string "' + str(select_string) + '"'
                    self.gui_warning(warning_message)
                    break

        return asset_tab_table_dic

    def get_asset_info(self, host_asset_file):
        """
        Parse host_asset.json and return host_asset_dic.
        """
        host_asset_dic = {}

        if os.path.exists(host_asset_file):
            common.bprint('Loading host asset file "' + str(host_asset_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')

            with open(host_asset_file, 'r') as HAF:
                host_asset_dic = json.loads(HAF.read())

        for host_ip in host_asset_dic.keys():
            # Add "host_ip" under host_asset_dic[host_ip].
            host_asset_dic[host_ip]['host_ip'] = host_ip

            # Add "host_name" under host_asset_dic[host_ip].
            if host_ip in self.host_list_class.host_ip_dic.keys():
                host_asset_dic[host_ip]['host_name'] = '  '.join(self.host_list_class.host_ip_dic[host_ip]['host_name'])
            else:
                host_asset_dic[host_ip]['host_name'] = ''

            # Add "groups" under host_asset_dic[host_ip].
            if host_ip in self.host_group_relationship_dic:
                host_asset_dic[host_ip]['groups'] = '  '.join(self.host_group_relationship_dic[host_ip])
            else:
                host_asset_dic[host_ip]['groups'] = ''

        return host_asset_dic

    def asset_to_host_tab(self):
        """
        Get selected host_ip list, and jump to HOST tab, generate self.host_tab_table.
        """
        specified_host_ip_list = []

        for row in range(self.asset_tab_table.rowCount()):
            host_ip = self.asset_tab_table.item(row, 0).text()
            specified_host_ip_list.append(host_ip)

        self.gen_host_tab_table(specified_host_ip_list)
        self.main_tab.setCurrentWidget(self.host_tab)

    def asset_to_stat_tab(self):
        """
        Get selected host_ip list, and jump to STAT tab, generate self.stat_tab_table.
        """
        specified_host_ip_list = []

        for row in range(self.asset_tab_table.rowCount()):
            host_ip = self.asset_tab_table.item(row, 0).text()
            specified_host_ip_list.append(host_ip)

        self.gen_stat_tab_table(specified_host_ip_list)
        self.main_tab.setCurrentWidget(self.stat_tab)

    def asset_to_run_tab(self):
        """
        Get selected host_ip list, and jump to RUN tab, generate self.run_tab_table.
        """
        self.run_tab_table_dic = {}

        for row in range(self.asset_tab_table.rowCount()):
            host_ip = self.asset_tab_table.item(row, 0).text()
            host_name = self.asset_tab_table.item(row, 1).text()
            groups = self.asset_tab_table.item(row, 2).text()
            self.run_tab_table_dic[host_ip] = {'hidden': False, 'state': Qt.Checked, 'host_name': host_name, 'groups': groups, 'output_message': ''}

        self.gen_run_tab_table()
        self.main_tab.setCurrentWidget(self.run_tab)
# For asset TAB (end) #

# For host TAB (begin) #
    def gen_host_tab(self):
        """
        Generate the HOST tab on batchRun GUI, show host_info.json informations.
        """
        if not self.host_tab.layout():
            # self.host_tab
            self.host_tab_qtree = QTreeWidget(self.host_tab)
            self.host_tab_qtree.itemDoubleClicked.connect(self.host_tab_qtree_double_clicked)

            self.host_tab_frame0 = QFrame(self.host_tab)
            self.host_tab_frame0.setFrameShadow(QFrame.Raised)
            self.host_tab_frame0.setFrameShape(QFrame.Box)

            self.host_tab_table = QTableWidget(self.host_tab)

            # self.host_tab - Grid
            host_tab_grid = QGridLayout()

            host_tab_grid.addWidget(self.host_tab_qtree, 0, 0, 2, 1)
            host_tab_grid.addWidget(self.host_tab_frame0, 0, 1)
            host_tab_grid.addWidget(self.host_tab_table, 1, 1)

            host_tab_grid.setRowStretch(0, 1)
            host_tab_grid.setRowStretch(1, 20)

            host_tab_grid.setColumnStretch(0, 1)
            host_tab_grid.setColumnStretch(1, 5)

            self.host_tab.setLayout(host_tab_grid)

        # Generate sub-frames
        self.gen_host_tab_qtree()
        self.gen_host_tab_frame0()
        self.gen_host_tab_table()

    def gen_host_tab_qtree(self):
        # self.host_tab_qtree
        self.host_tab_qtree.setColumnCount(1)
        self.host_tab_qtree.setHeaderLabels(['     Group  -  Sub_Group / Sub_Host', ])
        self.host_tab_qtree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.host_tab_qtree.header().setStretchLastSection(False)
        group_list = list(self.host_list_class.host_list_dic.keys())
        group_list.sort()

        for group in group_list:
            group_item = QTreeWidgetItem(self.host_tab_qtree)
            group_item.setText(0, group)
            group_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/G.png'))

            if ('sub_groups' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['sub_groups']:
                for sub_group in self.host_list_class.host_list_dic[group]['sub_groups']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, sub_group)
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/G.png'))
                    group_item.addChild(child_item)

            if ('exclude_groups' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['exclude_groups']:
                for exclude_group in self.host_list_class.host_list_dic[group]['exclude_groups']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, '~' + str(exclude_group))
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/G.png'))
                    group_item.addChild(child_item)

            if ('hosts' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['hosts']:
                for host in self.host_list_class.host_list_dic[group]['hosts']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, host)
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/H.png'))
                    group_item.addChild(child_item)

            if ('exclude_hosts' in self.host_list_class.host_list_dic[group]) and self.host_list_class.host_list_dic[group]['exclude_hosts']:
                for exclude_host in self.host_list_class.host_list_dic[group]['exclude_hosts']:
                    child_item = QTreeWidgetItem()
                    child_item.setText(0, '~' + str(exclude_host))
                    child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/h.png'))
                    group_item.addChild(child_item)

    def host_tab_qtree_double_clicked(self, item, column):
        """
        Select double clicked group/host on self.host_tab_frame0.
        """
        item_text = item.text(column)
        self.host_tab_host_line.setText('')

        for (i, qBox) in enumerate(self.host_tab_group_combo.checkBoxList):
            if qBox.text() == 'ALL':
                self.host_tab_group_combo.checkBoxList[i].setChecked(True)
            else:
                self.host_tab_group_combo.checkBoxList[i].setChecked(False)

        if item_text:
            group_list = copy.deepcopy(list(self.host_list_class.expanded_host_list_dic.keys()))

            if item_text in group_list:
                for (i, qBox) in enumerate(self.host_tab_group_combo.checkBoxList):
                    if qBox.text() == item_text:
                        self.host_tab_group_combo.checkBoxList[i].setChecked(True)
            else:
                self.host_tab_host_line.setText(item_text)

            self.gen_host_tab_table()

    def get_host_tab_host_info(self):
        """
        Get self.host_tab_frame0 host_info related items.
        """
        group_list = copy.deepcopy(list(self.host_list_class.expanded_host_list_dic.keys()))
        server_type_list = []
        os_list = []
        cpu_architecture_list = []
        cpu_thread_list = []
        thread_per_core_list = []
        cpu_model_list = []
        cpu_frequency_list = []
        mem_list = []
        swap_list = []

        if self.host_info_dic:
            for host_ip in self.host_info_dic.keys():
                if self.host_info_dic[host_ip]['server_type'] not in server_type_list:
                    server_type_list.append(self.host_info_dic[host_ip]['server_type'])

                if self.host_info_dic[host_ip]['os'] not in os_list:
                    os_list.append(self.host_info_dic[host_ip]['os'])

                if self.host_info_dic[host_ip]['cpu_architecture'] not in cpu_architecture_list:
                    cpu_architecture_list.append(self.host_info_dic[host_ip]['cpu_architecture'])

                if self.host_info_dic[host_ip]['cpu_thread'] not in cpu_thread_list:
                    cpu_thread_list.append(self.host_info_dic[host_ip]['cpu_thread'])

                if self.host_info_dic[host_ip]['thread_per_core'] not in thread_per_core_list:
                    thread_per_core_list.append(self.host_info_dic[host_ip]['thread_per_core'])

                if self.host_info_dic[host_ip]['cpu_model'] not in cpu_model_list:
                    cpu_model_list.append(self.host_info_dic[host_ip]['cpu_model'])

                if self.host_info_dic[host_ip]['cpu_frequency'] not in cpu_frequency_list:
                    cpu_frequency_list.append(self.host_info_dic[host_ip]['cpu_frequency'])

                if self.host_info_dic[host_ip]['mem_size'] not in mem_list:
                    mem_list.append(self.host_info_dic[host_ip]['mem_size'])

                if self.host_info_dic[host_ip]['swap_size'] not in swap_list:
                    swap_list.append(self.host_info_dic[host_ip]['swap_size'])

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
            swap_list.sort(key=int)

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

            for i, swap in enumerate(swap_list):
                if swap == 0:
                    swap_list[i] = ''
                else:
                    swap_list[i] = str(swap)

        return group_list, server_type_list, os_list, cpu_architecture_list, cpu_thread_list, thread_per_core_list, cpu_model_list, cpu_frequency_list, mem_list, swap_list

    def gen_host_tab_frame0(self):
        (group_list, server_type_list, os_list, cpu_architecture_list, cpu_thread_list, thread_per_core_list, cpu_model_list, cpu_frequency_list, mem_list, swap_list) = self.get_host_tab_host_info()

        # self.host_tab_frame0
        if self.host_tab_frame0.layout():
            self.init_combo_instance(combo_instance=self.host_tab_group_combo, item_list=group_list)
            self.init_combo_instance(combo_instance=self.host_tab_server_type_combo, item_list=server_type_list)
            self.init_combo_instance(combo_instance=self.host_tab_os_combo, item_list=os_list)
            self.init_combo_instance(combo_instance=self.host_tab_cpu_architecture_combo, item_list=cpu_architecture_list)
            self.init_combo_instance(combo_instance=self.host_tab_cpu_model_combo, item_list=cpu_model_list)
            self.init_combo_instance(combo_instance=self.host_tab_cpu_thread_combo, item_list=cpu_thread_list)
            self.init_combo_instance(combo_instance=self.host_tab_thread_per_core_combo, item_list=thread_per_core_list)
            self.init_combo_instance(combo_instance=self.host_tab_cpu_frequency_combo, item_list=cpu_frequency_list)
            self.init_combo_instance(combo_instance=self.host_tab_mem_combo, item_list=mem_list)
            return

        # "Group" item.
        host_tab_group_label = QLabel('Group', self.host_tab_frame0)
        host_tab_group_label.setStyleSheet("font-weight: bold;")
        host_tab_group_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_group_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_group_combo, item_list=group_list)

        # "Server_Type" item.
        host_tab_server_type_label = QLabel('Server_Type', self.host_tab_frame0)
        host_tab_server_type_label.setStyleSheet("font-weight: bold;")
        host_tab_server_type_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_server_type_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_server_type_combo, item_list=server_type_list)

        # "OS" item.
        host_tab_os_label = QLabel('OS', self.host_tab_frame0)
        host_tab_os_label.setStyleSheet("font-weight: bold;")
        host_tab_os_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_os_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_os_combo, item_list=os_list)

        # "Cpu_Arch" item.
        host_tab_cpu_architecture_label = QLabel('Cpu_Arch', self.host_tab_frame0)
        host_tab_cpu_architecture_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_architecture_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_architecture_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_cpu_architecture_combo, item_list=cpu_architecture_list)

        # "Cpu_Model" item.
        host_tab_cpu_model_label = QLabel('Cpu_Model', self.host_tab_frame0)
        host_tab_cpu_model_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_model_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_model_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_cpu_model_combo, item_list=cpu_model_list)

        # "Cpu_Thread" item.
        host_tab_cpu_thread_label = QLabel('Cpu_Thread', self.host_tab_frame0)
        host_tab_cpu_thread_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_thread_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_thread_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_cpu_thread_combo, item_list=cpu_thread_list)

        # "Thread_Per_Core" item.
        host_tab_thread_per_core_label = QLabel('Thread_Per_Core', self.host_tab_frame0)
        host_tab_thread_per_core_label.setStyleSheet("font-weight: bold;")
        host_tab_thread_per_core_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_thread_per_core_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_thread_per_core_combo, item_list=thread_per_core_list)

        # "Cpu_Freq" item.
        host_tab_cpu_frequency_label = QLabel('Cpu_Freq', self.host_tab_frame0)
        host_tab_cpu_frequency_label.setStyleSheet("font-weight: bold;")
        host_tab_cpu_frequency_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cpu_frequency_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_cpu_frequency_combo, item_list=cpu_frequency_list)

        # "MEM" item.
        host_tab_mem_label = QLabel('MEM', self.host_tab_frame0)
        host_tab_mem_label.setStyleSheet("font-weight: bold;")
        host_tab_mem_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_mem_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_mem_combo, item_list=mem_list)

        # "Swap" item.
        host_tab_swap_label = QLabel('Swap', self.host_tab_frame0)
        host_tab_swap_label.setStyleSheet("font-weight: bold;")
        host_tab_swap_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_swap_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.init_combo_instance(combo_instance=self.host_tab_swap_combo, item_list=swap_list)

        # "Scheduler" item.
        host_tab_scheduler_label = QLabel('Scheduler', self.host_tab_frame0)
        host_tab_scheduler_label.setStyleSheet("font-weight: bold;")
        host_tab_scheduler_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_scheduler_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_scheduler_combo()
        self.host_tab_scheduler_combo.activated.connect(lambda: self.set_host_tab_cluster_combo())

        # "Cluster" item.
        host_tab_cluster_label = QLabel('Cluster', self.host_tab_frame0)
        host_tab_cluster_label.setStyleSheet("font-weight: bold;")
        host_tab_cluster_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_cluster_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.host_tab_cluster_combo.activated.connect(lambda: self.set_host_tab_queues_combo())

        # "Queues" item.
        host_tab_queues_label = QLabel('Queues', self.host_tab_frame0)
        host_tab_queues_label.setStyleSheet("font-weight: bold;")
        host_tab_queues_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_queues_combo = common_pyqt5.QComboCheckBox(self.host_tab_frame0)
        self.set_host_tab_cluster_combo()

        # "Host" item.
        host_tab_host_label = QLabel('Host', self.host_tab_frame0)
        host_tab_host_label.setStyleSheet("font-weight: bold;")
        host_tab_host_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.host_tab_host_line = QLineEdit()
        self.host_tab_host_line.returnPressed.connect(self.gen_host_tab_table)

        host_tab_host_line_completer = common_pyqt5.get_completer(self.completer_host_list)
        self.host_tab_host_line.setCompleter(host_tab_host_line_completer)

        # empty item.
        host_tab_empty_label = QLabel('', self.host_tab_frame0)

        # "Check" button.
        host_tab_check_button = QPushButton('Check', self.host_tab_frame0)
        host_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        size_policy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        host_tab_check_button.setSizePolicy(size_policy)
        host_tab_check_button.clicked.connect(self.gen_host_tab_table)

        # "toAsset" button.
        host_tab_toasset_button = QPushButton('toAsset', self.host_tab_frame0)
        host_tab_toasset_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        host_tab_toasset_button.clicked.connect(self.host_to_asset_tab)

        # "toStat" button.
        host_tab_tostat_button = QPushButton('toStat', self.host_tab_frame0)
        host_tab_tostat_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        host_tab_tostat_button.clicked.connect(self.host_to_stat_tab)

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
        host_tab_frame0_grid.addWidget(host_tab_check_button, 0, 11, 3, 1)
        host_tab_frame0_grid.addWidget(host_tab_toasset_button, 0, 12)

        host_tab_frame0_grid.addWidget(host_tab_cpu_thread_label, 1, 0)
        host_tab_frame0_grid.addWidget(self.host_tab_cpu_thread_combo, 1, 1)
        host_tab_frame0_grid.addWidget(host_tab_thread_per_core_label, 1, 2)
        host_tab_frame0_grid.addWidget(self.host_tab_thread_per_core_combo, 1, 3)
        host_tab_frame0_grid.addWidget(host_tab_cpu_frequency_label, 1, 4)
        host_tab_frame0_grid.addWidget(self.host_tab_cpu_frequency_combo, 1, 5)
        host_tab_frame0_grid.addWidget(host_tab_mem_label, 1, 6)
        host_tab_frame0_grid.addWidget(self.host_tab_mem_combo, 1, 7)
        host_tab_frame0_grid.addWidget(host_tab_swap_label, 1, 8)
        host_tab_frame0_grid.addWidget(self.host_tab_swap_combo, 1, 9)
        host_tab_frame0_grid.addWidget(host_tab_empty_label, 1, 10)
        host_tab_frame0_grid.addWidget(host_tab_tostat_button, 1, 12)

        host_tab_frame0_grid.addWidget(host_tab_scheduler_label, 2, 0)
        host_tab_frame0_grid.addWidget(self.host_tab_scheduler_combo, 2, 1)
        host_tab_frame0_grid.addWidget(host_tab_cluster_label, 2, 2)
        host_tab_frame0_grid.addWidget(self.host_tab_cluster_combo, 2, 3)
        host_tab_frame0_grid.addWidget(host_tab_queues_label, 2, 4)
        host_tab_frame0_grid.addWidget(self.host_tab_queues_combo, 2, 5)
        host_tab_frame0_grid.addWidget(host_tab_host_label, 2, 6)
        host_tab_frame0_grid.addWidget(self.host_tab_host_line, 2, 7, 1, 3)
        host_tab_frame0_grid.addWidget(host_tab_empty_label, 2, 10)
        host_tab_frame0_grid.addWidget(host_tab_torun_button, 2, 12)

        host_tab_frame0_grid.setColumnStretch(0, 2)
        host_tab_frame0_grid.setColumnStretch(1, 2)
        host_tab_frame0_grid.setColumnStretch(2, 2)
        host_tab_frame0_grid.setColumnStretch(3, 2)
        host_tab_frame0_grid.setColumnStretch(4, 2)
        host_tab_frame0_grid.setColumnStretch(5, 2)
        host_tab_frame0_grid.setColumnStretch(6, 2)
        host_tab_frame0_grid.setColumnStretch(7, 2)
        host_tab_frame0_grid.setColumnStretch(8, 2)
        host_tab_frame0_grid.setColumnStretch(9, 2)
        host_tab_frame0_grid.setColumnStretch(10, 1)
        host_tab_frame0_grid.setColumnStretch(11, 1)
        host_tab_frame0_grid.setColumnStretch(12, 2)

        self.host_tab_frame0.setLayout(host_tab_frame0_grid)

    def init_combo_instance(self, combo_instance, item_list=[], checked_item_list=['ALL', ]):
        """
        Initialize combo instance.
        """
        combo_instance.clear()
        item_list.insert(0, 'ALL')

        for item in item_list:
            combo_instance.addCheckBoxItem(item, update_width=True)

        # Set to checked status for checked_queue_list.
        for (i, qBox) in enumerate(combo_instance.checkBoxList):
            if (qBox.text() in checked_item_list) and (qBox.isChecked() is False):
                combo_instance.checkBoxList[i].setChecked(True)

    def set_host_tab_scheduler_combo(self, checked_scheduler_list=['ALL', ]):
        """
        Set (initialize) self.host_tab_scheduler_combo.
        """
        self.host_tab_scheduler_combo.clear()

        scheduler_list = list(self.scheduler_cluster_queue_dic.keys())
        scheduler_list.sort()
        scheduler_list.insert(0, 'ALL')

        for scheduler in scheduler_list:
            self.host_tab_scheduler_combo.addCheckBoxItem(scheduler, update_width=True)

        # Set to checked status for checked_scheduler_list.
        for (i, qBox) in enumerate(self.host_tab_scheduler_combo.checkBoxList):
            if (qBox.text() in checked_scheduler_list) and (qBox.isChecked() is False):
                self.host_tab_scheduler_combo.checkBoxList[i].setChecked(True)

    def set_host_tab_cluster_combo(self, checked_cluster_list=['ALL', ]):
        """
        Set (initialize) self.host_tab_cluster_combo.
        """
        self.host_tab_cluster_combo.clear()

        specified_scheduler_list = self.host_tab_scheduler_combo.currentText().strip().split()
        cluster_list = []

        for scheduler in self.scheduler_cluster_queue_dic.keys():
            if ('ALL' in specified_scheduler_list) or (scheduler in specified_scheduler_list):
                for cluster in self.scheduler_cluster_queue_dic[scheduler].keys():
                    if cluster not in cluster_list:
                        cluster_list.append(cluster)

        cluster_list.sort()
        cluster_list.insert(0, 'ALL')

        for cluster in cluster_list:
            self.host_tab_cluster_combo.addCheckBoxItem(cluster, update_width=True)

        # Set to checked status for checked_cluster_list.
        for (i, qBox) in enumerate(self.host_tab_cluster_combo.checkBoxList):
            if (qBox.text() in checked_cluster_list) and (qBox.isChecked() is False):
                self.host_tab_cluster_combo.checkBoxList[i].setChecked(True)

        # Update self.host_tab_queues_combo.
        self.set_host_tab_queues_combo()

    def set_host_tab_queues_combo(self, checked_queue_list=['ALL', ]):
        """
        Set (initialize) self.host_tab_queues_combo.
        """
        self.host_tab_queues_combo.clear()

        specified_scheduler_list = self.host_tab_scheduler_combo.currentText().strip().split()
        specified_cluster_list = self.host_tab_cluster_combo.currentText().strip().split()
        queue_list = []

        for scheduler in self.scheduler_cluster_queue_dic.keys():
            if ('ALL' in specified_scheduler_list) or (scheduler in specified_scheduler_list):
                for cluster in self.scheduler_cluster_queue_dic[scheduler].keys():
                    if ('ALL' in specified_cluster_list) or (cluster in specified_cluster_list):
                        for queue in self.scheduler_cluster_queue_dic[scheduler][cluster]:
                            if queue not in queue_list:
                                queue_list.append(queue)

        queue_list.sort()
        queue_list.insert(0, 'ALL')

        for queue in queue_list:
            self.host_tab_queues_combo.addCheckBoxItem(queue, update_width=True)

        # Set to checked status for checked_queue_list.
        for (i, qBox) in enumerate(self.host_tab_queues_combo.checkBoxList):
            if (qBox.text() in checked_queue_list) and (qBox.isChecked() is False):
                self.host_tab_queues_combo.checkBoxList[i].setChecked(True)

    def gen_host_tab_table(self, specified_host_ip_list=[]):
        orig_host_tab_table_dic = self.collect_host_tab_table_info()

        if not specified_host_ip_list:
            host_tab_table_dic = orig_host_tab_table_dic
        else:
            host_tab_table_dic = {}

            for specified_host_ip in specified_host_ip_list:
                if specified_host_ip in orig_host_tab_table_dic.keys():
                    host_tab_table_dic[specified_host_ip] = orig_host_tab_table_dic[specified_host_ip]

        # self.host_tab_table
        self.host_tab_table.setShowGrid(True)
        self.host_tab_table.setSortingEnabled(True)
        self.host_tab_table.setColumnCount(0)
        self.host_tab_table_title_list = ['host_ip', 'host_name', 'groups', 'server_type', 'os', 'cpu_arch', 'cpu_model', 'cpu_thread', 'thread_per_core', 'cpu_freq (GHz)', 'mem (GB)', 'swap (GB)', 'ssh_port', 'scheduler', 'cluster', 'queues']
        self.host_tab_table.setColumnCount(len(self.host_tab_table_title_list))
        self.host_tab_table.setHorizontalHeaderLabels(self.host_tab_table_title_list)
        self.host_tab_table.horizontalHeader().setContextMenuPolicy(Qt.CustomContextMenu)
        self.host_tab_table.horizontalHeader().customContextMenuRequested.connect(self.hide_host_tab_table_column)

        # Fill self.host_tab_table items.
        self.host_tab_table.setRowCount(0)
        self.host_tab_table.setRowCount(len(host_tab_table_dic))

        i = -1

        for host_ip in host_tab_table_dic.keys():
            groups = host_tab_table_dic[host_ip]['groups']
            host_name = host_tab_table_dic[host_ip]['host_name']
            server_type = host_tab_table_dic[host_ip].get('server_type', '')
            os = host_tab_table_dic[host_ip].get('os', '')
            cpu_architecture = host_tab_table_dic[host_ip].get('cpu_architecture', '')
            cpu_thread = host_tab_table_dic[host_ip].get('cpu_thread', 0)
            thread_per_core = host_tab_table_dic[host_ip].get('thread_per_core', 0)
            cpu_model = host_tab_table_dic[host_ip].get('cpu_model', '')
            cpu_frequency = host_tab_table_dic[host_ip].get('cpu_frequency', 0.0)
            mem_size = host_tab_table_dic[host_ip].get('mem_size', 0)
            swap_size = host_tab_table_dic[host_ip].get('swap_size', 0)
            ssh_port = host_tab_table_dic[host_ip].get('ssh_port', '')
            scheduler = host_tab_table_dic[host_ip].get('scheduler', '')
            cluster = host_tab_table_dic[host_ip].get('cluster', '')
            queue_list = host_tab_table_dic[host_ip].get('queues', [])

            i += 1

            # Fill "host_ip" item.
            j = 0
            item = QTableWidgetItem(host_ip)
            self.host_tab_table.setItem(i, j, item)

            # Fill "host_name" item.
            j += 1
            item = QTableWidgetItem(host_name)
            self.host_tab_table.setItem(i, j, item)

            # Fill "group" item.
            j += 1
            item = QTableWidgetItem(groups)
            self.host_tab_table.setItem(i, j, item)

            # Fill "server_type" item.
            j += 1
            item = QTableWidgetItem(server_type)

            if not server_type:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "os" item.
            j += 1
            item = QTableWidgetItem(os)

            if not os:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "cpu_arch" item.
            j += 1
            item = QTableWidgetItem(cpu_architecture)

            if not cpu_architecture:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "cpu_model" item.
            j += 1
            item = QTableWidgetItem(cpu_model)

            if not cpu_model:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "cpu_thread" item.
            j += 1
            item = QTableWidgetItem()

            if cpu_thread:
                item.setData(Qt.DisplayRole, cpu_thread)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "thread_per_core" item.
            j += 1
            item = QTableWidgetItem()

            if thread_per_core:
                item.setData(Qt.DisplayRole, thread_per_core)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "cpu_freq" item.
            j += 1
            item = QTableWidgetItem()

            if cpu_frequency:
                item.setData(Qt.DisplayRole, cpu_frequency)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "mem" item.
            j += 1
            item = QTableWidgetItem()

            if mem_size:
                item.setData(Qt.DisplayRole, mem_size)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "swap" item.
            j += 1
            item = QTableWidgetItem()

            if swap_size:
                item.setData(Qt.DisplayRole, swap_size)
            else:
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "ssh_port" item.
            j += 1
            item = QTableWidgetItem(ssh_port)
            self.host_tab_table.setItem(i, j, item)

            # Fill "schduler" item.
            j += 1
            item = QTableWidgetItem(scheduler)

            if scheduler == '_':
                item.setBackground(QBrush(Qt.red))

            self.host_tab_table.setItem(i, j, item)

            # Fill "cluster" item.
            j += 1
            item = QTableWidgetItem(cluster)
            self.host_tab_table.setItem(i, j, item)

            # Fill "queues" item.
            j += 1
            item = QTableWidgetItem('  '.join(queue_list))
            self.host_tab_table.setItem(i, j, item)

        self.host_tab_table.resizeColumnsToContents()

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
        specified_swap_list = self.host_tab_swap_combo.currentText().strip().split()
        specified_scheduler_list = self.host_tab_scheduler_combo.currentText().strip().split()
        specified_cluster_list = self.host_tab_cluster_combo.currentText().strip().split()
        specified_queue_list = self.host_tab_queues_combo.currentText().strip().split()
        specified_host_list = self.host_tab_host_line.text().strip().split()

        # Preprocess int/float items.
        for item_list in [specified_cpu_thread_list, specified_thread_per_core_list, specified_mem_list, specified_swap_list]:
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

                if 'ALL' not in specified_swap_list:
                    if ((not self.host_info_dic[host_ip]['swap_size']) and specified_swap_list) or (self.host_info_dic[host_ip]['swap_size'] and (self.host_info_dic[host_ip]['swap_size'] not in specified_swap_list)):
                        continue

                # Exclude with scheduler/cluster/queues.
                scheduler = ''
                cluster = ''
                queue_list = []

                if (host_ip in self.host_queue_dic.keys()) and self.host_queue_dic[host_ip]:
                    scheduler = self.host_queue_dic[host_ip]['scheduler']
                    cluster = self.host_queue_dic[host_ip]['cluster']
                    queue_list = self.host_queue_dic[host_ip]['queues']

                if 'ALL' not in specified_scheduler_list:
                    if ((not scheduler) and specified_scheduler_list) or (scheduler and (scheduler not in specified_scheduler_list)):
                        continue

                if 'ALL' not in specified_cluster_list:
                    if ((not cluster) and specified_cluster_list) or (cluster and (cluster not in specified_cluster_list)):
                        continue

                if 'ALL' not in specified_queue_list:
                    if ((not queue_list) and specified_queue_list) or (queue_list and all(queue not in specified_queue_list for queue in queue_list)):
                        continue

                # Exclude with host.
                if specified_host_list and ((host_ip not in specified_host_list) and all(host_name not in specified_host_list for host_name in self.host_list_class.host_ip_dic[host_ip]['host_name'])):
                    continue

                # Save host_ip related info into host_tab_table_dic.
                host_tab_table_dic[host_ip] = self.host_info_dic[host_ip]

                if isinstance(host_tab_table_dic[host_ip]['host_name'], list):
                    host_tab_table_dic[host_ip]['host_name'] = '  '.join(host_tab_table_dic[host_ip]['host_name'])

                host_tab_table_dic[host_ip]['scheduler'] = scheduler
                host_tab_table_dic[host_ip]['cluster'] = cluster
                host_tab_table_dic[host_ip]['queues'] = queue_list

                if 'ssh_port' in self.host_list_class.host_ip_dic[host_ip]:
                    ssh_port = self.host_list_class.host_ip_dic[host_ip]['ssh_port']
                    host_tab_table_dic[host_ip]['ssh_port'] = ssh_port

        # Update groups setting for host_ip.
        for host_ip in host_tab_table_dic.keys():
            if host_ip in self.host_group_relationship_dic.keys():
                host_tab_table_dic[host_ip]['groups'] = ' '.join(self.host_group_relationship_dic[host_ip])
            else:
                host_tab_table_dic[host_ip]['groups'] = ''

        return host_tab_table_dic

    def host_to_asset_tab(self):
        """
        Get selected host_ip list, and jump to ASSET tab, generate self.asset_tab_table.
        """
        specified_host_ip_list = []

        for row in range(self.host_tab_table.rowCount()):
            host_ip = self.host_tab_table.item(row, 0).text()
            specified_host_ip_list.append(host_ip)

        self.gen_asset_tab_table(specified_host_ip_list)
        self.main_tab.setCurrentWidget(self.asset_tab)

    def host_to_stat_tab(self):
        """
        Get selected host_ip list, and jump to STAT tab, generate self.stat_tab_table.
        """
        specified_host_ip_list = []

        for row in range(self.host_tab_table.rowCount()):
            host_ip = self.host_tab_table.item(row, 0).text()
            specified_host_ip_list.append(host_ip)

        self.gen_stat_tab_table(specified_host_ip_list)
        self.main_tab.setCurrentWidget(self.stat_tab)

    def host_to_run_tab(self):
        """
        Get selected host_ip list, and jump to RUN tab, generate self.run_tab_table.
        """
        self.run_tab_table_dic = {}

        for row in range(self.host_tab_table.rowCount()):
            host_ip = self.host_tab_table.item(row, 0).text()
            host_name = self.host_tab_table.item(row, 1).text()
            groups = self.host_tab_table.item(row, 2).text()
            self.run_tab_table_dic[host_ip] = {'hidden': False, 'state': Qt.Checked, 'host_name': host_name, 'groups': groups, 'output_message': ''}

        self.gen_run_tab_table()
        self.main_tab.setCurrentWidget(self.run_tab)

    def hide_host_tab_table_column(self, pos):
        """
        Used to hide specified title item on self.host_tab_table.
        """
        menu = QMenu(self)

        for i in range(self.host_tab_table.columnCount()):
            action = menu.addAction(self.host_tab_table.horizontalHeaderItem(i).text())
            action.setCheckable(True)
            action.setChecked(not self.host_tab_table.isColumnHidden(i))
            action.toggled.connect(lambda checked, col=i: self.host_tab_table.setColumnHidden(col, not checked))

        menu.exec_(self.host_tab_table.mapToGlobal(pos))
# For host TAB (end) #

# For stat TAB (begin) #
    def gen_stat_tab(self):
        """
        Generate the STAT tab on batchRun GUI, show host_stat.json informations.
        """
        if not self.stat_tab.layout():
            # self.stat_tab
            self.stat_tab_frame0 = QFrame(self.stat_tab)
            self.stat_tab_frame0.setFrameShadow(QFrame.Raised)
            self.stat_tab_frame0.setFrameShape(QFrame.Box)

            self.stat_tab_table = QTableWidget(self.stat_tab)
            self.stat_tab_table.itemClicked.connect(self.stat_tab_check_click)

            # self.stat_tab - Grid
            stat_tab_grid = QGridLayout()

            stat_tab_grid.addWidget(self.stat_tab_frame0, 0, 0)
            stat_tab_grid.addWidget(self.stat_tab_table, 1, 0)

            stat_tab_grid.setRowStretch(0, 1)
            stat_tab_grid.setRowStretch(1, 20)

            self.stat_tab.setLayout(stat_tab_grid)

        # Generate sub-frames
        self.gen_stat_tab_frame0()
        self.gen_stat_tab_table()

    def gen_stat_tab_frame0(self):
        # self.stat_tab_frame0
        if self.stat_tab_frame0.layout():
            self.update_stat_tab_time_combo()
            return

        # "Date" item.
        stat_tab_date_label = QLabel('Date', self.stat_tab_frame0)
        stat_tab_date_label.setStyleSheet("font-weight: bold;")
        stat_tab_date_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.stat_tab_date_edit = QDateEdit(self.stat_tab_frame0)
        self.stat_tab_date_edit.setDisplayFormat('yyyyMMdd')
        self.stat_tab_date_edit.setMinimumDate(QDate.currentDate().addDays(-3652))
        self.stat_tab_date_edit.setCalendarPopup(True)
        self.stat_tab_date_edit.setDate(QDate.currentDate())
        self.stat_tab_date_edit.dateChanged.connect(self.update_stat_tab_time_combo)

        # "Time" item.
        stat_tab_time_label = QLabel('Time', self.stat_tab_frame0)
        stat_tab_time_label.setStyleSheet("font-weight: bold;")
        stat_tab_time_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.stat_tab_time_combo = QComboBox(self.stat_tab_frame0)
        self.update_stat_tab_time_combo()

        # "Select" item.
        stat_tab_select_label = QLabel('Select', self.stat_tab_frame0)
        stat_tab_select_label.setStyleSheet("font-weight: bold;")
        stat_tab_select_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.stat_tab_select_line = QLineEdit()
        self.stat_tab_select_line.returnPressed.connect(self.gen_stat_tab_table)

        # empty item.
        stat_tab_empty_label = QLabel('', self.stat_tab_frame0)

        # "Check" button.
        stat_tab_check_button = QPushButton('Check', self.stat_tab_frame0)
        stat_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        stat_tab_check_button.clicked.connect(self.gen_stat_tab_table)

        # "toAsset" button.
        stat_tab_toasset_button = QPushButton('toAsset', self.stat_tab_frame0)
        stat_tab_toasset_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        stat_tab_toasset_button.clicked.connect(self.stat_to_asset_tab)

        # "toHost" button.
        stat_tab_tohost_button = QPushButton('toHost', self.stat_tab_frame0)
        stat_tab_tohost_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        stat_tab_tohost_button.clicked.connect(self.stat_to_host_tab)

        # "toRun" button.
        stat_tab_torun_button = QPushButton('toRun', self.stat_tab_frame0)
        stat_tab_torun_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        stat_tab_torun_button.clicked.connect(self.stat_to_run_tab)

        # self.stat_tab_frame0 - Grid
        stat_tab_frame0_grid = QGridLayout()

        stat_tab_frame0_grid.addWidget(stat_tab_date_label, 0, 0)
        stat_tab_frame0_grid.addWidget(self.stat_tab_date_edit, 0, 1)
        stat_tab_frame0_grid.addWidget(stat_tab_time_label, 0, 2)
        stat_tab_frame0_grid.addWidget(self.stat_tab_time_combo, 0, 3)
        stat_tab_frame0_grid.addWidget(stat_tab_select_label, 0, 4)
        stat_tab_frame0_grid.addWidget(self.stat_tab_select_line, 0, 5)
        stat_tab_frame0_grid.addWidget(stat_tab_empty_label, 0, 6)
        stat_tab_frame0_grid.addWidget(stat_tab_check_button, 0, 7)
        stat_tab_frame0_grid.addWidget(stat_tab_toasset_button, 0, 8)
        stat_tab_frame0_grid.addWidget(stat_tab_tohost_button, 0, 9)
        stat_tab_frame0_grid.addWidget(stat_tab_torun_button, 0, 10)

        stat_tab_frame0_grid.setColumnStretch(0, 2)
        stat_tab_frame0_grid.setColumnStretch(1, 2)
        stat_tab_frame0_grid.setColumnStretch(2, 2)
        stat_tab_frame0_grid.setColumnStretch(3, 2)
        stat_tab_frame0_grid.setColumnStretch(4, 2)
        stat_tab_frame0_grid.setColumnStretch(5, 10)
        stat_tab_frame0_grid.setColumnStretch(6, 1)
        stat_tab_frame0_grid.setColumnStretch(7, 2)
        stat_tab_frame0_grid.setColumnStretch(8, 2)
        stat_tab_frame0_grid.setColumnStretch(9, 2)
        stat_tab_frame0_grid.setColumnStretch(10, 2)

        self.stat_tab_frame0.setLayout(stat_tab_frame0_grid)

    def update_stat_tab_time_combo(self):
        """
        Update self.stat_tab_time_combo with self.stat_tab_date_edit updating.
        """
        self.stat_tab_time_combo.clear()

        time_list = []
        specified_date = self.stat_tab_date_edit.date().toString('yyyyMMdd')
        host_stat_dir = str(config.db_path) + '/host_stat/' + str(specified_date)

        if os.path.exists(host_stat_dir):
            for dir_name in os.listdir(host_stat_dir):
                host_stat_file = str(host_stat_dir) + '/' + str(dir_name) + '/host_stat.json'

                if re.match(r'^\d{6}$', dir_name) and os.path.exists(host_stat_file):
                    time_list.append(dir_name)

        if time_list:
            time_list.sort()

            for dir_name in time_list:
                self.stat_tab_time_combo.addItem(dir_name)

            self.stat_tab_time_combo.setCurrentIndex(len(time_list)-1)

    def gen_stat_tab_table(self, specified_host_ip_list=[]):
        orig_stat_tab_table_dic = self.collect_stat_tab_table_info()

        if not specified_host_ip_list:
            stat_tab_table_dic = orig_stat_tab_table_dic
        else:
            stat_tab_table_dic = {}

            for specified_host_ip in specified_host_ip_list:
                if specified_host_ip in orig_stat_tab_table_dic.keys():
                    stat_tab_table_dic[specified_host_ip] = orig_stat_tab_table_dic[specified_host_ip]

        # self.stat_tab_table
        self.stat_tab_table.setShowGrid(True)
        self.stat_tab_table.setSortingEnabled(True)
        self.stat_tab_table.setColumnCount(0)
        self.stat_tab_table_title_list = ['host_ip', 'host_name', 'groups', 'up_days', 'users', 'tasks', 'r1m', 'r5m', 'r15m', 'cpu_thread', 'cpu_id', 'cpu_wa', 'mem_total', 'mem_avail', 'swap_total', 'swap_used', 'tmp_total', 'tmp_avail']
        self.stat_tab_table.setColumnCount(len(self.stat_tab_table_title_list))
        self.stat_tab_table.setHorizontalHeaderLabels(self.stat_tab_table_title_list)

        self.stat_tab_table.setColumnWidth(0, 120)
        self.stat_tab_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.stat_tab_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.stat_tab_table.setColumnWidth(3, 65)
        self.stat_tab_table.setColumnWidth(4, 50)
        self.stat_tab_table.setColumnWidth(5, 60)
        self.stat_tab_table.setColumnWidth(6, 55)
        self.stat_tab_table.setColumnWidth(7, 55)
        self.stat_tab_table.setColumnWidth(8, 55)
        self.stat_tab_table.setColumnWidth(9, 85)
        self.stat_tab_table.setColumnWidth(10, 55)
        self.stat_tab_table.setColumnWidth(11, 60)
        self.stat_tab_table.setColumnWidth(12, 80)
        self.stat_tab_table.setColumnWidth(13, 80)
        self.stat_tab_table.setColumnWidth(14, 85)
        self.stat_tab_table.setColumnWidth(15, 85)
        self.stat_tab_table.setColumnWidth(16, 80)
        self.stat_tab_table.setColumnWidth(17, 80)

        # Fill self.stat_tab_table items.
        self.stat_tab_table.setRowCount(0)
        self.stat_tab_table.setRowCount(len(stat_tab_table_dic))

        i = -1

        for host_ip in stat_tab_table_dic.keys():
            i += 1

            # Fill "host_ip" item.
            j = 0
            item = QTableWidgetItem(host_ip)
            self.stat_tab_table.setItem(i, j, item)

            # Fill "host_name" item.
            j += 1
            item = QTableWidgetItem(stat_tab_table_dic[host_ip]['host_name'])

            if not stat_tab_table_dic[host_ip]['host_name']:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "group" item.
            j += 1
            item = QTableWidgetItem(stat_tab_table_dic[host_ip]['groups'])

            if not stat_tab_table_dic[host_ip]['groups']:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "up_days" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['up_days'])

            if stat_tab_table_dic[host_ip]['up_days'] == 0:
                item.setBackground(QBrush(QColor(255, 102, 0)))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "users" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['users'])

            if stat_tab_table_dic[host_ip]['users'] == 0:
                item.setBackground(QBrush(QColor(255, 102, 0)))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "tasks" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['tasks'])

            if stat_tab_table_dic[host_ip]['tasks'] == 0:
                item.setBackground(QBrush(Qt.red))

            if stat_tab_table_dic[host_ip]['r1m'] >= stat_tab_table_dic[host_ip]['cpu_thread']:
                item.setFont(QFont('song', 9, QFont.Bold))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "r1m" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['r1m'])

            if stat_tab_table_dic[host_ip]['r1m'] >= stat_tab_table_dic[host_ip]['cpu_thread']:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "r5m" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['r5m'])

            if stat_tab_table_dic[host_ip]['r5m'] >= stat_tab_table_dic[host_ip]['cpu_thread']:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "r15m" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['r15m'])

            if stat_tab_table_dic[host_ip]['r15m'] >= stat_tab_table_dic[host_ip]['cpu_thread']:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "cpu_thread" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['cpu_thread'])
            self.stat_tab_table.setItem(i, j, item)

            # Fill "cpu_id" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['cpu_id'])

            if (stat_tab_table_dic[host_ip]['cpu_id'] == 0) or (stat_tab_table_dic[host_ip]['cpu_id'] == 100):
                item.setBackground(QBrush(Qt.red))
            elif (stat_tab_table_dic[host_ip]['cpu_id'] <= 1) or (stat_tab_table_dic[host_ip]['cpu_id'] >= 99):
                item.setBackground(QBrush(QColor(255, 102, 0)))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "cpu_wa" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['cpu_wa'])

            if 10 <= stat_tab_table_dic[host_ip]['cpu_wa'] < 30:
                item.setBackground(QBrush(QColor(255, 102, 0)))
            elif stat_tab_table_dic[host_ip]['cpu_wa'] >= 30:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "mem_total" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['mem_total'])

            if stat_tab_table_dic[host_ip]['mem_total'] == 0:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "mem_avail" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['mem_avail'])

            if 0 < stat_tab_table_dic[host_ip]['mem_avail'] <= stat_tab_table_dic[host_ip]['mem_total']/10:
                item.setBackground(QBrush(QColor(255, 102, 0)))
            elif stat_tab_table_dic[host_ip]['mem_avail'] == 0:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "swap_total" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['swap_total'])

            if stat_tab_table_dic[host_ip]['swap_total'] == 0:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "swap_used" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['swap_used'])

            if (stat_tab_table_dic[host_ip]['swap_total'] > 0) and (stat_tab_table_dic[host_ip]['swap_used'] >= stat_tab_table_dic[host_ip]['swap_total']/10):
                item.setBackground(QBrush(QColor(255, 102, 0)))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "tmp_total" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['tmp_total'])

            if stat_tab_table_dic[host_ip]['tmp_total'] == 0:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

            # Fill "tmp_avail" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, stat_tab_table_dic[host_ip]['tmp_avail'])

            if 0 < stat_tab_table_dic[host_ip]['tmp_avail'] <= stat_tab_table_dic[host_ip]['tmp_total']/10:
                item.setBackground(QBrush(QColor(255, 102, 0)))
            elif stat_tab_table_dic[host_ip]['tmp_avail'] == 0:
                item.setBackground(QBrush(Qt.red))

            self.stat_tab_table.setItem(i, j, item)

    def collect_stat_tab_table_info(self):
        """
        Collect host stat info with specified date/time/host.
        """
        stat_tab_table_dic = {}
        specified_date = self.stat_tab_date_edit.date().toString('yyyyMMdd')
        specified_time = self.stat_tab_time_combo.currentText().strip()
        select_string = self.stat_tab_select_line.text().strip()

        if specified_date and specified_time:
            host_stat_file = str(config.db_path) + '/host_stat/' + str(specified_date) + '/' + str(specified_time) + '/host_stat.json'
            host_stat_dic = self.get_stat_info(host_stat_file)

            if not select_string:
                stat_tab_table_dic = host_stat_dic
            else:
                for host_ip in host_stat_dic.keys():
                    try:
                        if eval(select_string, {}, host_stat_dic[host_ip]):
                            stat_tab_table_dic[host_ip] = host_stat_dic[host_ip]
                    except Exception:
                        stat_tab_table_dic = host_stat_dic
                        warning_message = 'Invalid select string "' + str(select_string) + '"'
                        self.gui_warning(warning_message)
                        break

        return stat_tab_table_dic

    def get_stat_info(self, host_stat_file):
        """
        Parse host_stat.json and return host_stat_dic.
        """
        host_stat_dic = {}

        if os.path.exists(host_stat_file):
            common.bprint('Loading host stat file "' + str(host_stat_file) + '" ...', date_format='%Y-%m-%d %H:%M:%S')

            with open(host_stat_file, 'r') as HSF:
                host_stat_dic = json.loads(HSF.read())

        for host_ip in host_stat_dic.keys():
            # Add "host_ip" under host_stat_dic[host_ip].
            host_stat_dic[host_ip]['host_ip'] = host_ip

            # Add "host_name" under host_stat_dic[host_ip].
            if host_ip in self.host_list_class.host_ip_dic.keys():
                host_stat_dic[host_ip]['host_name'] = '  '.join(self.host_list_class.host_ip_dic[host_ip]['host_name'])
            else:
                host_stat_dic[host_ip]['host_name'] = ''

            # Add "groups" under host_stat_dic[host_ip].
            if host_ip in self.host_group_relationship_dic:
                host_stat_dic[host_ip]['groups'] = '  '.join(self.host_group_relationship_dic[host_ip])
            else:
                host_stat_dic[host_ip]['groups'] = ''

        return host_stat_dic

    def stat_to_asset_tab(self):
        """
        Get selected host_ip list, and jump to ASSET tab, generate self.asset_tab_table.
        """
        specified_host_ip_list = []

        for row in range(self.stat_tab_table.rowCount()):
            host_ip = self.stat_tab_table.item(row, 0).text()
            specified_host_ip_list.append(host_ip)

        self.gen_asset_tab_table(specified_host_ip_list)
        self.main_tab.setCurrentWidget(self.asset_tab)

    def stat_to_host_tab(self):
        """
        Get selected host_ip list, and jump to HOST tab, generate self.host_tab_table.
        """
        specified_host_ip_list = []

        for row in range(self.stat_tab_table.rowCount()):
            host_ip = self.stat_tab_table.item(row, 0).text()
            specified_host_ip_list.append(host_ip)

        self.gen_host_tab_table(specified_host_ip_list)
        self.main_tab.setCurrentWidget(self.host_tab)

    def stat_to_run_tab(self):
        """
        Get selected host_ip list, and jump to RUN tab, generate self.run_tab_table.
        """
        self.run_tab_table_dic = {}

        for row in range(self.stat_tab_table.rowCount()):
            host_ip = self.stat_tab_table.item(row, 0).text()
            host_name = self.stat_tab_table.item(row, 1).text()
            groups = self.stat_tab_table.item(row, 2).text()
            self.run_tab_table_dic[host_ip] = {'hidden': False, 'state': Qt.Checked, 'host_name': host_name, 'groups': groups, 'output_message': ''}

        self.gen_run_tab_table()
        self.main_tab.setCurrentWidget(self.run_tab)

    def stat_tab_check_click(self, item=None):
        """
        If r1m >= cpu_thread and top_file exists, show top_file.
        """
        if item is not None:
            if item.column() == 5:
                current_row = self.stat_tab_table.currentRow()
                r1m = float(self.stat_tab_table.item(current_row, 6).text().strip())
                cpu_thread = int(self.stat_tab_table.item(current_row, 9).text().strip())

                if r1m >= cpu_thread:
                    specified_date = self.stat_tab_date_edit.date().toString('yyyyMMdd')
                    specified_time = self.stat_tab_time_combo.currentText().strip()
                    host_ip = self.stat_tab_table.item(current_row, 0).text().strip()
                    top_file = str(config.db_path) + '/host_stat/' + str(specified_date) + '/' + str(specified_time) + '/' + str(host_ip) + '.top'

                    if os.path.exists(top_file):
                        common.bprint('Show top file "' + str(top_file) + '".', date_format='%Y-%m-%d %H:%M:%S')
                        self.my_show_top_file = ShowTopFile(top_file)
                        self.my_show_top_file.start()
                    else:
                        common.bprint('Not find top file "' + str(top_file) + '".', date_format='%Y-%m-%d %H:%M:%S', level='Warning')
# For stat TAB (end) #

# For run TAB (begin) #
    def gen_run_tab(self):
        """
        Generate the RUN tab on batchRun GUI, run specified command and show command output message.
        """
        if not self.run_tab.layout():
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
        if self.run_tab_frame0.layout():
            return

        # "Timeout" item.
        run_tab_timeout_label = QLabel('Timeout', self.run_tab_frame0)
        run_tab_timeout_label.setStyleSheet("font-weight: bold;")
        run_tab_timeout_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.run_tab_timeout_line = QLineEdit()
        self.run_tab_timeout_line.setText(str(config.parallel_timeout))

        # "Command" item.
        run_tab_command_label = QLabel('Command', self.run_tab_frame0)
        run_tab_command_label.setStyleSheet("font-weight: bold;")
        run_tab_command_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.run_tab_command_line = QLineEdit()
        self.run_tab_command_line.returnPressed.connect(self.run_tab_run_command)

        # "Select" item.
        run_tab_select_label = QLabel('Select', self.run_tab_frame0)
        run_tab_select_label.setStyleSheet("font-weight: bold;")
        run_tab_select_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.run_tab_select_line = QLineEdit()
        self.run_tab_select_line.returnPressed.connect(self.gen_run_tab_table)

        # empty item.
        run_tab_empty_label = QLabel('', self.run_tab_frame0)

        # "Run" button.
        run_tab_run_button = QPushButton('Run', self.run_tab_frame0)
        run_tab_run_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        run_tab_run_button.clicked.connect(self.run_tab_run_command)

        # "Check" button.
        run_tab_check_button = QPushButton('Check', self.run_tab_frame0)
        run_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        run_tab_check_button.clicked.connect(self.gen_run_tab_table)

        # self.run_tab_frame0 - Grid
        run_tab_frame0_grid = QGridLayout()

        run_tab_frame0_grid.addWidget(run_tab_timeout_label, 0, 0)
        run_tab_frame0_grid.addWidget(self.run_tab_timeout_line, 0, 1)
        run_tab_frame0_grid.addWidget(run_tab_empty_label, 0, 2)
        run_tab_frame0_grid.addWidget(run_tab_command_label, 0, 3)
        run_tab_frame0_grid.addWidget(self.run_tab_command_line, 0, 4)
        run_tab_frame0_grid.addWidget(run_tab_empty_label, 0, 5)
        run_tab_frame0_grid.addWidget(run_tab_run_button, 0, 6)
        run_tab_frame0_grid.addWidget(run_tab_select_label, 1, 0)
        run_tab_frame0_grid.addWidget(self.run_tab_select_line, 1, 1, 1, 4)
        run_tab_frame0_grid.addWidget(run_tab_empty_label, 1, 5)
        run_tab_frame0_grid.addWidget(run_tab_check_button, 1, 6)

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
        Generate self.run_tab_table with self.run_tab_table_dic.
        """
        self.collect_run_tab_table_info()

        # self.run_tab_table
        self.run_tab_table.setShowGrid(True)
        self.run_tab_table.setSortingEnabled(False)
        self.run_tab_table.setColumnCount(0)
        self.run_tab_table_title_list = ['host_ip', 'host_name', 'groups', 'output_message']
        self.run_tab_table.setColumnCount(len(self.run_tab_table_title_list))
        self.run_tab_table.setHorizontalHeaderLabels(self.run_tab_table_title_list)

        self.run_tab_table.setColumnWidth(0, 140)
        self.run_tab_table.setColumnWidth(1, 130)
        self.run_tab_table.setColumnWidth(2, 130)
        self.run_tab_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

        # Fill self.run_tab_table items.
        self.run_tab_table.setRowCount(0)
        run_tab_table_row_count = 0

        for host_ip in self.run_tab_table_dic.keys():
            if not self.run_tab_table_dic[host_ip]['hidden']:
                run_tab_table_row_count += 1

        self.run_tab_table.setRowCount(run_tab_table_row_count)

        run_command = self.run_tab_command_line.text().strip()
        i = -1

        for host_ip in self.run_tab_table_dic.keys():
            if not self.run_tab_table_dic[host_ip]['hidden']:
                i += 1

                # Fill "host_ip" item.
                j = 0
                item = QTableWidgetItem(host_ip)
                state = self.run_tab_table_dic[host_ip]['state']
                item.setCheckState(state)
                self.run_tab_table.setItem(i, j, item)

                # Fill "host_name" item.
                j += 1
                host_name = self.run_tab_table_dic[host_ip]['host_name']
                item = QTableWidgetItem(host_name)
                self.run_tab_table.setItem(i, j, item)

                # Fill "groups" item.
                j += 1
                groups = self.run_tab_table_dic[host_ip]['groups']
                item = QTableWidgetItem(groups)
                self.run_tab_table.setItem(i, j, item)

                # Fill "output_message" item.
                j += 1
                output_message = self.run_tab_table_dic[host_ip]['output_message']
                item = QTableWidgetItem(output_message)

                if 'pexpect.exceptions.TIMEOUT' in output_message:
                    item.setForeground(QBrush(QColor(255, 102, 0)))
                    self.update_run_tab_frame1('*Warning*: Host "' + str(host_ip) + '" ssh timeout.', color='orange')
                elif "'default'" in output_message:
                    item.setForeground(QBrush(QColor(255, 102, 0)))
                    self.update_run_tab_frame1('*Warning*: Host "' + str(host_ip) + '" ssh fail.', color='orange')
                elif (run_command == 'hostname') and (output_message != host_name) and output_message:
                    if (' ' in host_name) and re.search(r'\b' + str(output_message) + r'\b', host_name):
                        item.setForeground(QBrush(Qt.white))
                    else:
                        item.setForeground(QBrush(Qt.red))
                        self.update_run_tab_frame1('*Error*: Host "' + str(host_ip) + '", hostname is "' + str(host_name) + '" in host.list, but "' + str(output_message) + '" with hostname command.', color='red')
                else:
                    item.setForeground(QBrush(Qt.white))

                self.run_tab_table.setItem(i, j, item)

    def collect_run_tab_table_info(self):
        """
        Collect host ip info with specified select condition.
        """
        select_string = self.run_tab_select_line.text().strip()

        if not select_string:
            for host_ip in self.run_tab_table_dic.keys():
                self.run_tab_table_dic[host_ip]['hidden'] = False
                self.run_tab_table_dic[host_ip]['state'] = Qt.Checked
        else:
            for host_ip in self.run_tab_table_dic.keys():
                try:
                    if eval(select_string, {}, self.run_tab_table_dic[host_ip]):
                        self.run_tab_table_dic[host_ip]['hidden'] = False
                        self.run_tab_table_dic[host_ip]['state'] = Qt.Checked
                    else:
                        self.run_tab_table_dic[host_ip]['hidden'] = True
                        self.run_tab_table_dic[host_ip]['state'] = Qt.Unchecked
                except Exception:
                    for host_ip in self.run_tab_table_dic.keys():
                        self.run_tab_table_dic[host_ip]['hidden'] = False
                        self.run_tab_table_dic[host_ip]['state'] = Qt.Checked

                    warning_message = 'Invalid select string "' + str(select_string) + '"'
                    self.gui_warning(warning_message)
                    break

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
                self.run_tab_table_dic[host_ip]['state'] = new_state

    def run_tab_table_item_clicked(self, item):
        """
        If item changed on self.run_tab_table, update host_ip state setting.
        """
        if item.column() == 0:
            host_ip = item.text().strip()

            if self.run_tab_table_dic[host_ip]['state'] != item.checkState():
                self.run_tab_table_dic[host_ip]['state'] = item.checkState()

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
            # Filter illegal command.
            format_command = ' '.join(run_command.split())
            format_command = re.sub(r'\\', '', format_command)

            for illegal_command in config.illegal_command_list:
                if (format_command in config.illegal_command_list) or re.match(r'^' + str(illegal_command) + '$', format_command):
                    my_show_message = ShowMessage('Error', 'Illegal command "' + str(run_command) + '".')
                    my_show_message.start()
                    time.sleep(3)
                    my_show_message.terminate()
                    self.update_run_tab_frame1('*Error*: Illegal command "' + str(run_command) + '".', color='red')
                    return

            # Check timeout setting.
            timeout = self.run_tab_timeout_line.text().strip()

            if not re.match(r'^\d+$', timeout):
                my_show_message = ShowMessage('Error', 'Wrong format of Timeout "' + str(timeout) + '", it must be an integer.')
                my_show_message.start()
                time.sleep(3)
                my_show_message.terminate()
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
                for host_ip in self.run_tab_table_dic.keys():
                    if self.run_tab_table_dic[host_ip]['state'] == Qt.Checked:
                        HLF.write(str(host_ip) + '\n')
                        run_tab_selected_host_ip_list.append(host_ip)

            # Call batch_run to execute specified command.
            self.update_run_tab_frame1('* Run command "' + str(run_command) + '" parallel with below batch_run command.')

            output_file = str(tmp_batchRun_user_current_dir) + '/HOST'

            if '"' in run_command:
                batch_run_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run --hosts ' + str(host_list_file) + " --command '" + str(run_command) + "' --parallel " + str(len(run_tab_selected_host_ip_list)) + ' --timeout ' + str(timeout) + ' --output_message_level 1 --output_file ' + str(output_file)
            else:
                batch_run_command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run --hosts ' + str(host_list_file) + ' --command \"' + str(run_command) + '\" --parallel ' + str(len(run_tab_selected_host_ip_list)) + ' --timeout ' + str(timeout) + ' --output_message_level 1 --output_file ' + str(output_file)

            my_show_message = ShowMessage('Info', '快马加鞭X' + str(len(run_tab_selected_host_ip_list)) + ', running ...')
            my_show_message.start()
            self.update_run_tab_frame1('  ' + str(batch_run_command))
            os.system(batch_run_command)
            self.update_run_tab_frame1('  Done')
            my_show_message.terminate()

            # Clean up 'output_message' on self.run_tab_table_dic.
            for host_ip in self.run_tab_table_dic.keys():
                self.run_tab_table_dic[host_ip]['output_message'] = ''

            # Collect command output message.
            for file_name in os.listdir(tmp_batchRun_user_current_dir):
                if file_name in self.run_tab_table_dic:
                    file_path = str(tmp_batchRun_user_current_dir) + '/' + str(file_name)

                    with open(file_path, 'r') as FP:
                        self.run_tab_table_dic[file_name]['output_message'] = FP.read().strip()

            # Update self.run_tab_table.
            self.gen_run_tab_table()

    def gen_run_tab_frame1(self):
        if not self.run_tab_frame1.layout():
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
        if not self.run_tab_frame2.layout():
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

        # empty item.
        log_tab_empty_label = QLabel('', self.log_tab_frame0)

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
        log_tab_frame0_grid.addWidget(log_tab_empty_label, 0, 8)
        log_tab_frame0_grid.addWidget(log_tab_search_button, 0, 9)

        log_tab_frame0_grid.setColumnStretch(0, 2)
        log_tab_frame0_grid.setColumnStretch(1, 3)
        log_tab_frame0_grid.setColumnStretch(2, 2)
        log_tab_frame0_grid.setColumnStretch(3, 2)
        log_tab_frame0_grid.setColumnStretch(4, 2)
        log_tab_frame0_grid.setColumnStretch(5, 2)
        log_tab_frame0_grid.setColumnStretch(6, 2)
        log_tab_frame0_grid.setColumnStretch(7, 4)
        log_tab_frame0_grid.setColumnStretch(8, 1)
        log_tab_frame0_grid.setColumnStretch(9, 2)

        self.log_tab_frame0.setLayout(log_tab_frame0_grid)

    def set_log_tab_user_combo(self, checked_user_list=['ALL', ]):
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
            self.log_tab_user_combo.addCheckBoxItem(user, update_width=True)

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

        if os.path.exists(log_dir):
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
        self.log_tab_table_title_list = ['time', 'user', 'login_user', 'command', 'log']
        self.log_tab_table.setColumnCount(len(self.log_tab_table_title_list))
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

            # Fill "time" item.
            j = 0
            item = QTableWidgetItem(log_dic['time'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "user" item.
            j += 1
            item = QTableWidgetItem(log_dic['user'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "login_user" item.
            j += 1
            item = QTableWidgetItem(log_dic['login_user'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "command" item.
            j += 1
            item = QTableWidgetItem(log_dic['command'])
            self.log_tab_table.setItem(i, j, item)

            # Fill "log" item.
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
                    try:
                        line_dic = json.loads(line)

                        if specified_begin_date <= line_dic['date'] <= specified_end_date:
                            if (not specified_info) or re.search(specified_info, line_dic['command']):
                                time = datetime.datetime.strptime(str(line_dic['date']) + str(line_dic['time']), '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
                                self.log_dic_list.insert(0, {'time': time, 'user': line_dic['user'], 'login_user': line_dic['login_user'], 'command': line_dic['command'], 'log': line_dic['log']})
                    except Exception:
                        pass

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
    def export_scan_table(self):
        self.export_table('scan', self.scan_tab_table, self.scan_tab_table_title_list)

    def export_asset_table(self):
        self.export_table('asset', self.asset_tab_table, self.asset_tab_table_title_list)

    def export_host_table(self):
        self.export_table('host', self.host_tab_table, self.host_tab_table_title_list)

    def export_stat_table(self):
        self.export_table('stat', self.stat_tab_table, self.stat_tab_table_title_list)

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

    def import_run_list(self):
        """
        Import host_ip list with specified file on RUN tab.
        """
        (run_list_file, file_type) = QFileDialog.getOpenFileName(self, 'Import run list', '.', "All Files (*)")

        # Get host_ip_list from run_list_file.
        host_ip_list = []

        if os.path.splitext(run_list_file)[1].lower() == '.csv':
            try:
                csv_dic = common.read_csv(run_list_file)
            except Exception as error:
                warning_message = 'Failed on opening ' + str(run_list_file) + ' for read, ' + str(error)
                self.gui_warning(warning_message)
                return

            if 'host_ip' not in csv_dic:
                warning_message = 'Not "host_ip" key on ' + str(run_list_file) + '.'
                self.gui_warning(warning_message)
                return
            else:
                for host_ip in csv_dic['host_ip'].values():
                    host_ip_list.append(host_ip)
        else:
            try:
                with open(run_list_file, 'r') as RLF:
                    for line in RLF.readlines():
                        line = line.strip()
                        host_ip_list.append(line)
            except Exception as error:
                warning_message = 'Failed on opening ' + str(run_list_file) + ' for read, ' + str(error)
                self.gui_warning(warning_message)
                return

        # Update self.run_tab_table_dic with host_ip_list.
        self.run_tab_table_dic = {}

        for host_ip in host_ip_list:
            if not common.is_ip(host_ip):
                warning_message = 'Invalid host ip "' + str(host_ip) + '" on ' + str(run_list_file) + '.'
                self.gui_warning(warning_message)
                return

            # Add "host_name" under self.run_tab_table_dic[host_ip].
            if host_ip in self.host_list_class.host_ip_dic.keys():
                host_name = '  '.join(self.host_list_class.host_ip_dic[host_ip]['host_name'])
            else:
                host_name = ''

            # Add "groups" under self.run_tab_table_dic[host_ip].
            if host_ip in self.host_group_relationship_dic:
                groups = '  '.join(self.host_group_relationship_dic[host_ip])
            else:
                groups = ''

            self.run_tab_table_dic[host_ip] = {'hidden': False, 'state': Qt.Checked, 'host_name': host_name, 'groups': groups, 'output_message': ''}

        # Trun to RUN tab and rebuild self.run_tab_table.
        if host_ip_list:
            self.main_tab.setCurrentWidget(self.run_tab)
            self.gen_run_tab_table()

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
        self.cmd = f'xterm -bg black -fg gray -into {str(int(self.winId()))} -geometry 200x200 -sb -l -lc -lf /dev/stdout -e /bin/bash -c "ps -o tt=;bash" | tee'
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


class ShowTopFile(QThread):
    """
    Start tool show_top_file to show host top information with specified file.
    """
    def __init__(self, top_file):
        super(ShowTopFile, self).__init__()
        self.top_file = top_file

    def run(self):
        command = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/tools/show_top_file --top_file ' + str(self.top_file)
        os.system(command)


class ShowMessage(QThread):
    """
    Show message with tool message.
    """
    def __init__(self, title, message):
        super(ShowMessage, self).__init__()
        self.title = title
        self.message = re.sub(r'"', '\\"', message)

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
