# -*- coding: utf-8 -*-
################################
# File Name   : show_top_file.py
# Author      : liyanqing.1987
# Created On  : 2024-12-20 16:42:24
# Description :
################################
import os
import re
import sys
import argparse

from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt

sys.path.insert(0, str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common_pyqt5

os.environ['PYTHONUNBUFFERED'] = '1'


def read_args():
    """
    Read in arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--top_file',
                        required=True,
                        default='',
                        help='Specify top file path.')

    args = parser.parse_args()

    return args.top_file


class ShowTopFile(QMainWindow):
    def __init__(self, top_file):
        super().__init__()
        self.top_file = top_file
        self.init_ui()

    def init_ui(self):
        # Add main_tab
        self.main_tab = QTabWidget(self)
        self.setCentralWidget(self.main_tab)

        self.main_frame = QFrame(self.main_tab)

        # Grid
        main_grid = QGridLayout()
        main_grid.addWidget(self.main_frame, 0, 0)
        self.main_tab.setLayout(main_grid)

        # Generate main_table
        self.gen_main_frame()

        # Show main window
        self.setWindowTitle(self.top_file)

        common_pyqt5.auto_resize(self, 1200, 600)
        common_pyqt5.center_window(self)

    def gen_main_frame(self):
        self.main_table = QTableWidget(self.main_frame)

        # Grid
        main_frame_grid = QGridLayout()
        main_frame_grid.addWidget(self.main_table, 0, 0)
        self.main_frame.setLayout(main_frame_grid)

        self.gen_main_table()

    def parse_top_file(self):
        """
        Parse top_file and return top_line_list.
        'top -bc -n 1' output message format:
        ----------------
        top - 19:05:54 up 268 days,  7:15, 98 users,  load average: 2.99, 3.02, 3.28
        Tasks: 1334 total,   1 running, 1329 sleeping,   0 stopped,   4 zombie
        %Cpu(s):  7.1 us,  1.6 sy,  0.0 ni, 91.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
        KiB Mem : 13289836+total,  5669876 free, 11326056 used, 11590243+buff/cache
        KiB Swap:  8050684 total,  4564524 free,  3486160 used. 11681983+avail Mem

           PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
         66159 root      20   0  174036   3896   1972 R  15.8  0.0   0:00.08 top -bc -n 1
            14 root      20   0       0      0      0 S   5.3  0.0  11:47.34 [ksoftirqd/1]
        123575 root      20   0  648644  28684   3364 S   5.3  0.0 210:35.80 /usr/libexec/gsd-color
        ----------------
        """
        top_dic_list = []
        pid_compile = re.compile(r'^\s*PID\s+USER\s+.*COMMAND\s*$')
        line_compile = re.compile(r'\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s+')

        with open(self.top_file, 'r') as TF:
            mark = False

            for line in TF.readlines():
                if mark and line_compile.match(line):
                    my_match = line_compile.match(line)
                    pid = int(my_match.group(1))
                    user = my_match.group(2)
                    pr = my_match.group(3)
                    ni = int(my_match.group(4))
                    virt = my_match.group(5)
                    res = my_match.group(6)
                    shr = my_match.group(7)
                    s = my_match.group(8)
                    cpu = float(my_match.group(9))
                    mem = float(my_match.group(10))
                    time = my_match.group(11)
                    command = my_match.group(12)
                    top_dic = {'pid': pid, 'user': user, 'pr': pr, 'ni': ni, 'virt': virt, 'res': res, 'shr': shr, 's': s, 'cpu': cpu, 'mem': mem, 'time': time, 'command': command}
                    top_dic_list.append(top_dic)
                elif pid_compile.match(line):
                    mark = True

        return top_dic_list

    def gen_main_table(self):
        self.main_table.setShowGrid(True)
        self.main_table.setSortingEnabled(True)
        self.main_table.setColumnCount(12)
        self.main_table.setHorizontalHeaderLabels(['PID', 'USER', 'PR', 'NI', 'VIRT', 'RES', 'SHR', 'S', '%CPU', '%MEM', 'TIME+', 'COMMAND'])

        # Set column width
        self.main_table.setColumnWidth(0, 60)
        self.main_table.setColumnWidth(1, 80)
        self.main_table.setColumnWidth(2, 40)
        self.main_table.setColumnWidth(3, 40)
        self.main_table.setColumnWidth(4, 80)
        self.main_table.setColumnWidth(5, 80)
        self.main_table.setColumnWidth(6, 80)
        self.main_table.setColumnWidth(7, 30)
        self.main_table.setColumnWidth(8, 60)
        self.main_table.setColumnWidth(9, 60)
        self.main_table.setColumnWidth(10, 90)
        self.main_table.horizontalHeader().setSectionResizeMode(11, QHeaderView.Stretch)

        # Set item
        top_dic_list = self.parse_top_file()
        self.main_table.setRowCount(len(top_dic_list))

        i = -1

        for top_dic in top_dic_list:
            i += 1

            # Fill "PID" item.
            j = 0
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, top_dic['pid'])
            self.main_table.setItem(i, j, item)

            # Fill "USER" item.
            j += 1
            item = QTableWidgetItem(top_dic['user'])
            self.main_table.setItem(i, j, item)

            # Fill "PR" item.
            j += 1
            item = QTableWidgetItem(top_dic['pr'])
            self.main_table.setItem(i, j, item)

            # Fill "NI" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, top_dic['ni'])
            self.main_table.setItem(i, j, item)

            # Fill "VIRT" item.
            j += 1
            item = QTableWidgetItem(top_dic['virt'])
            self.main_table.setItem(i, j, item)

            # Fill "RES" item.
            j += 1
            item = QTableWidgetItem(top_dic['res'])
            self.main_table.setItem(i, j, item)

            # Fill "SHR" item.
            j += 1
            item = QTableWidgetItem(top_dic['shr'])
            self.main_table.setItem(i, j, item)

            # Fill "S" item.
            j += 1
            item = QTableWidgetItem(top_dic['s'])
            self.main_table.setItem(i, j, item)

            # Fill "%CPU" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, top_dic['cpu'])
            self.main_table.setItem(i, j, item)

            # Fill "%MEM" item.
            j += 1
            item = QTableWidgetItem()
            item.setData(Qt.DisplayRole, top_dic['mem'])
            self.main_table.setItem(i, j, item)

            # Fill "TIME+" item.
            j += 1
            item = QTableWidgetItem(top_dic['time'])
            self.main_table.setItem(i, j, item)

            # Fill "COMMAND" item.
            j += 1
            item = QTableWidgetItem(top_dic['command'])
            self.main_table.setItem(i, j, item)


################
# Main Process #
################
def main():
    top_file = read_args()
    app = QApplication(sys.argv)
    my_show = ShowTopFile(top_file)
    my_show.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
