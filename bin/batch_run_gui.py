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
import math
import time
import socket
import getpass
import datetime
import webbrowser
import qdarkstyle
import base64
import threading
import subprocess

from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QAction, qApp, QTabWidget, QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QMessageBox, QLineEdit, QHeaderView, QFileDialog, QTextEdit, QTreeWidget, QTreeWidgetItem, QDateEdit, QSplitter, QComboBox, QMenu, QSizePolicy, QAbstractItemView, QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem, QGraphicsItem, QToolTip, QVBoxLayout, QHBoxLayout, QProgressDialog
from PyQt5.QtGui import QIcon, QBrush, QFont, QColor, QPainter, QPen, QPixmap, QTextLength, QTextTableFormat, QTextCharFormat, QTextBlockFormat, QTextImageFormat, QPainterPath
from PyQt5.QtCore import Qt, QThread, QProcess, QDate, QPointF, QRect, QTimer, QUrl, QEvent, pyqtSignal

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/config')
import config

sys.path.append(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/common')
import common
import common_pyqt5
import common_ai
import common_ai_log

os.environ['PYTHONUNBUFFERED'] = '1'
CURRENT_USER = getpass.getuser()
VERSION = 'V2.4'
VERSION_DATE = '2026.06.14'


class LogDataReadyEvent(QEvent):
    EVENT_TYPE = QEvent.Type(QEvent.registerEventType())

    def __init__(self):
        super().__init__(self.EVENT_TYPE)


EOL_OS_PATTERNS = [
    (re.compile(r'CentOS.*[56][\.\s]', re.IGNORECASE), 'CentOS 5/6 - EOL'),
    (re.compile(r'CentOS.*7[\.\s]', re.IGNORECASE), 'CentOS 7 - EOL (2024-06)'),
    (re.compile(r'CentOS.*8[\.\s]', re.IGNORECASE), 'CentOS 8 - EOL (2021-12)'),
    (re.compile(r'Red Hat.*[56][\.\s]', re.IGNORECASE), 'RHEL 5/6 - EOL'),
    (re.compile(r'Red Hat.*7[\.\s]', re.IGNORECASE), 'RHEL 7 - EOL (2024-06)'),
    (re.compile(r'Ubuntu.*1[2468]\.04', re.IGNORECASE), 'Ubuntu LTS < 20.04 - EOL'),
    (re.compile(r'SUSE.*1[12][\.\s]', re.IGNORECASE), 'SLES 11/12 - EOL'),
]


# Solve some unexpected warning message.
if 'XDG_RUNTIME_DIR' not in os.environ:
    user = getpass.getuser()
    os.environ['XDG_RUNTIME_DIR'] = '/tmp/runtime-' + str(user)

    if not os.path.exists(os.environ['XDG_RUNTIME_DIR']):
        os.makedirs(os.environ['XDG_RUNTIME_DIR'])
        os.chmod(os.environ['XDG_RUNTIME_DIR'], 0o777)


def _ip_sort_key(ip):
    """Sort IP addresses by numeric octets, not lexicographically."""
    try:
        return tuple(int(o) for o in ip.split('.'))
    except (ValueError, AttributeError):
        return (0, 0, 0, 0)


class IPRectItem(QGraphicsRectItem):
    """
    IP square item in the network diagram.
    Green for active, dark gray for inactive.
    Colors are chosen for dark background (qdarkstyle).
    """
    def __init__(self, ip_address, ip_info, parent=None):
        super().__init__(parent)
        self.ip_address = ip_address
        self.ip_info = ip_info
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.PointingHandCursor)

        if ip_info.get('connectivity', False):
            self.setBrush(QBrush(QColor(60, 160, 60)))
        else:
            self.setBrush(QBrush(QColor(70, 70, 70)))

        self.setPen(QPen(QColor(150, 150, 150), 1))

        self.label = QGraphicsTextItem(self)
        self.label.setPlainText(ip_address)
        font = QFont()
        font.setPointSize(5)
        self.label.setFont(font)
        self.label.setDefaultTextColor(QColor(220, 220, 220))

    def setRect(self, *args):
        super().setRect(*args)

        if hasattr(self, 'label') and self.label:
            r = self.rect()
            label_rect = self.label.boundingRect()
            self.label.setPos(
                r.x() + (r.width() - label_rect.width()) / 2,
                r.y() + (r.height() - label_rect.height()) / 2
            )

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            info = self.ip_info
            lines = [
                'IP: ' + str(self.ip_address),
            ]

            if info.get('host_name'):
                lines.append('Host: ' + str(info['host_name']))

            if info.get('groups'):
                lines.append('Groups: ' + str(info['groups']))

            if info.get('server_type'):
                lines.append('Type: ' + str(info['server_type']))

            if info.get('os'):
                lines.append('OS: ' + str(info['os']))

            if info.get('cpu_architecture'):
                lines.append('CPU Arch: ' + str(info['cpu_architecture']))

            if info.get('cpu_thread'):
                lines.append('CPU Thread: ' + str(info['cpu_thread']))

            if info.get('cpu_model'):
                lines.append('CPU Model: ' + str(info['cpu_model']))

            if info.get('cpu_frequency'):
                freq = str(info['cpu_frequency'])

                if info.get('cpu_frequency_unit'):
                    freq += ' ' + str(info['cpu_frequency_unit'])

                lines.append('CPU Freq: ' + freq)

            if info.get('mem_size'):
                mem = str(info['mem_size'])

                if info.get('mem_size_unit'):
                    mem += ' ' + str(info['mem_size_unit'])

                lines.append('Memory: ' + mem)

            if info.get('swap_size'):
                swap = str(info['swap_size'])

                if info.get('swap_size_unit'):
                    swap += ' ' + str(info['swap_size_unit'])

                lines.append('Swap: ' + swap)

            QToolTip.showText(event.screenPos(), '\n'.join(lines), None, QRect(), 8000)
        super().mousePressEvent(event)


class NetworkRectItem(QGraphicsRectItem):
    """
    Network CIDR rectangle in the network diagram.
    Solid border, contains IP squares. Draggable within zone.
    Colors chosen for dark background.
    """
    def __init__(self, network_cidr, active_count, total_count, parent=None):
        super().__init__(parent)
        self.network_cidr = network_cidr
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)

        self.setPen(QPen(QColor(140, 160, 200), 2))

        title_text = str(network_cidr) + ' (' + str(active_count) + '/' + str(total_count) + ')'
        self.title = QGraphicsTextItem(self)
        usage_ratio = active_count / total_count if total_count > 0 else 0

        if usage_ratio > 0.8:
            self.title.setHtml(
                '<span style="color:#b4d2ff;font-weight:bold;font-size:9pt;">' + str(network_cidr)
                + ' </span><span style="color:#ff5555;font-weight:bold;font-size:9pt;">('
                + str(active_count) + '/' + str(total_count) + ')</span>'
            )
        else:
            font = QFont()
            font.setBold(True)
            font.setPointSize(9)
            self.title.setFont(font)
            self.title.setDefaultTextColor(QColor(180, 210, 255))
            self.title.setPlainText(title_text)

    def setRect(self, *args):
        super().setRect(*args)

        if hasattr(self, 'title') and self.title:
            r = self.rect()
            self.title.setPos(r.x() + 5, r.y() + 2)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionChange:
            zone = self.parentItem()

            if isinstance(zone, ZoneRectItem) and not zone._recalcing:
                value = self._clampPosition(value)

        if change == QGraphicsItem.ItemPositionHasChanged:
            zone = self.parentItem()

            if isinstance(zone, ZoneRectItem) and not zone._recalcing:
                zone.recalcBounds()

        return super().itemChange(change, value)

    def _clampPosition(self, new_pos):
        """Iteratively clamp to zone bounds and push away from siblings until stable."""
        zone = self.parentItem()

        if not isinstance(zone, ZoneRectItem):
            return new_pos

        my_rect = self.rect()
        min_gap = 8

        for _ in range(20):
            # Step 1: Clamp to zone boundaries (zone rect is always at (0,0))
            zone_rect = zone.rect()
            max_x = zone_rect.width() - my_rect.width()
            max_y = zone_rect.height() - my_rect.height()

            if new_pos.x() < 0:
                new_pos.setX(0)
            elif new_pos.x() > max_x:
                new_pos.setX(max_x)

            if new_pos.y() < 0:
                new_pos.setY(0)
            elif new_pos.y() > max_y:
                new_pos.setY(max_y)

            # Step 2: Find closest overlapping sibling
            best_push = None
            best_dist = float('inf')

            for sibling in zone.childItems():
                if not isinstance(sibling, NetworkRectItem) or sibling is self:
                    continue

                s_rect = sibling.rect()
                s_pos = sibling.pos()

                if (new_pos.x() < s_pos.x() + s_rect.width() + min_gap
                        and new_pos.x() + my_rect.width() + min_gap > s_pos.x()
                        and new_pos.y() < s_pos.y() + s_rect.height() + min_gap
                        and new_pos.y() + my_rect.height() + min_gap > s_pos.y()):

                    push_right = (s_pos.x() + s_rect.width() + min_gap) - new_pos.x()
                    push_left = (new_pos.x() + my_rect.width() + min_gap) - s_pos.x()
                    push_down = (s_pos.y() + s_rect.height() + min_gap) - new_pos.y()
                    push_up = (new_pos.y() + my_rect.height() + min_gap) - s_pos.y()

                    candidates = [
                        (abs(push_right), QPointF(new_pos.x() + push_right, new_pos.y())),
                        (abs(push_left), QPointF(new_pos.x() - push_left, new_pos.y())),
                        (abs(push_down), QPointF(new_pos.x(), new_pos.y() + push_down)),
                        (abs(push_up), QPointF(new_pos.x(), new_pos.y() - push_up)),
                    ]
                    candidates.sort(key=lambda x: x[0])

                    if candidates[0][0] < best_dist:
                        best_dist = candidates[0][0]
                        best_push = candidates[0][1]

            if best_push is None:
                break  # No more overlaps, stable

            new_pos = best_push

        return new_pos


class ZoneRectItem(QGraphicsRectItem):
    """
    Zone boundary rectangle in the network diagram.
    Dashed border, no fill, contains network rectangles. Draggable.
    Zone rect always stays at (0,0) — recalcBounds shifts children.
    Colors chosen for dark background.
    """
    def __init__(self, zone_name, parent=None):
        super().__init__(parent)
        self.zone_name = zone_name
        self._recalcing = False
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)

        self.setPen(QPen(QColor(255, 180, 50), 2, Qt.DashLine))
        self.setBrush(QBrush(Qt.NoBrush))

        self.title = QGraphicsTextItem(self)
        self.title.setPlainText(zone_name)
        font = QFont()
        font.setBold(True)
        font.setPointSize(11)
        self.title.setFont(font)
        self.title.setDefaultTextColor(QColor(255, 200, 80))

    def setRect(self, *args):
        super().setRect(*args)

        if hasattr(self, 'title') and self.title:
            r = self.rect()
            self.title.setPos(r.x() + 8, r.y() + 4)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionChange:
            value = self._clampPosition(value)

        return super().itemChange(change, value)

    def _clampPosition(self, new_pos):
        """Iteratively clamp to avoid sibling zone overlap."""
        scene = self.scene()

        if not scene:
            return new_pos

        my_rect = self.rect()
        min_gap = 15

        for _ in range(20):
            best_push = None
            best_dist = float('inf')

            for item in scene.items():
                if not isinstance(item, ZoneRectItem) or item is self:
                    continue

                s_rect = item.rect()
                s_pos = item.pos()

                if (new_pos.x() < s_pos.x() + s_rect.width() + min_gap
                        and new_pos.x() + my_rect.width() + min_gap > s_pos.x()
                        and new_pos.y() < s_pos.y() + s_rect.height() + min_gap
                        and new_pos.y() + my_rect.height() + min_gap > s_pos.y()):
                    push_right = (s_pos.x() + s_rect.width() + min_gap) - new_pos.x()
                    push_left = (new_pos.x() + my_rect.width() + min_gap) - s_pos.x()
                    push_down = (s_pos.y() + s_rect.height() + min_gap) - new_pos.y()
                    push_up = (new_pos.y() + my_rect.height() + min_gap) - s_pos.y()
                    candidates = [
                        (abs(push_right), QPointF(new_pos.x() + push_right, new_pos.y())),
                        (abs(push_left), QPointF(new_pos.x() - push_left, new_pos.y())),
                        (abs(push_down), QPointF(new_pos.x(), new_pos.y() + push_down)),
                        (abs(push_up), QPointF(new_pos.x(), new_pos.y() - push_up)),
                    ]
                    candidates.sort(key=lambda x: x[0])

                    if candidates[0][0] < best_dist:
                        best_dist = candidates[0][0]
                        best_push = candidates[0][1]

            if best_push is None:
                break

            new_pos = best_push
        return new_pos

    def recalcBounds(self):
        """
        Recalculate zone bounding rect to minimally enclose child networks.
        Shifts children to keep zone rect origin at (0,0).
        Pushes neighboring zones away if expansion causes overlap.
        """
        if self._recalcing:
            return

        self._recalcing = True
        children = self.childItems()

        if not children:
            self._recalcing = False
            return

        net_children = [c for c in children if isinstance(c, NetworkRectItem)]

        if not net_children:
            self._recalcing = False
            return

        min_x = min(n.pos().x() for n in net_children)
        min_y = min(n.pos().y() for n in net_children)
        max_x = max(n.pos().x() + n.rect().width() for n in net_children)
        max_y = max(n.pos().y() + n.rect().height() for n in net_children)

        pad = 20
        title_h = 24

        new_x = min_x - pad
        new_y = min_y - pad - title_h
        new_w = max_x - min_x + pad * 2
        new_h = max_y - min_y + pad * 2 + title_h

        old_w = self.rect().width()
        old_h = self.rect().height()

        # Shift child networks to keep zone rect at (0,0)
        if new_x != 0 or new_y != 0:
            for n in net_children:
                n.setPos(n.pos().x() - new_x, n.pos().y() - new_y)

        self.setRect(0, 0, new_w, new_h)

        # If zone expanded, push neighboring zones away to prevent overlap
        if new_w > old_w or new_h > old_h:
            self._resolveZoneOverlaps()

        self._recalcing = False

    def _resolveZoneOverlaps(self):
        """Push neighboring zones away if this zone's expansion causes overlap."""
        scene = self.scene()
        if not scene:
            return
        my_rect = self.rect()
        my_pos = self.pos()
        min_gap = 15

        for item in list(scene.items()):
            if not isinstance(item, ZoneRectItem) or item is self:
                continue

            s_rect = item.rect()
            s_pos = item.pos()

            if (my_pos.x() < s_pos.x() + s_rect.width() + min_gap
                    and my_pos.x() + my_rect.width() + min_gap > s_pos.x()
                    and my_pos.y() < s_pos.y() + s_rect.height() + min_gap
                    and my_pos.y() + my_rect.height() + min_gap > s_pos.y()):

                push_right = (my_pos.x() + my_rect.width() + min_gap) - s_pos.x()
                push_down = (my_pos.y() + my_rect.height() + min_gap) - s_pos.y()
                push_left = (s_pos.x() + s_rect.width() + min_gap) - my_pos.x()
                push_up = (s_pos.y() + s_rect.height() + min_gap) - my_pos.y()

                candidates = [
                    (abs(push_right), QPointF(s_pos.x() + push_right, s_pos.y())),
                    (abs(push_down), QPointF(s_pos.x(), s_pos.y() + push_down)),
                    (abs(push_left), QPointF(s_pos.x() - push_left, s_pos.y())),
                    (abs(push_up), QPointF(s_pos.x(), s_pos.y() - push_up)),
                ]
                candidates.sort(key=lambda x: x[0])
                item.setPos(candidates[0][1])


class ZoomableGraphicsView(QGraphicsView):
    """
    QGraphicsView with mouse-wheel zoom and drag-to-pan.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self._zoom_factor = 1.15

    def wheelEvent(self, event):
        if event.angleDelta().y() > 0:
            factor = self._zoom_factor
        else:
            factor = 1.0 / self._zoom_factor

        self.scale(factor, factor)


class MainWindow(QMainWindow):
    """
    Main window of batchRun.
    """
    def __init__(self):
        super().__init__()

        # Init variables.
        self.init_var()

        # Init diagram state.
        self._diagram_ever_generated = False

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
        self.main_tab.currentChanged.connect(self._on_main_tab_changed)
        self.setCentralWidget(self.main_tab)

        # Define sub-tabs
        self.network_tab = QWidget()
        self.asset_tab = QWidget()
        self.host_tab = QWidget()
        self.stat_tab = QWidget()
        self.run_tab = QWidget()
        self.log_tab = QWidget()
        self.ai_tab = QWidget()

        # Add the sub-tabs into main Tab widget
        if self.network_scan_dic:
            self.main_tab.addTab(self.network_tab, 'NETWORK')

        if self.host_asset_dic:
            self.main_tab.addTab(self.asset_tab, 'ASSET')

        self.main_tab.addTab(self.host_tab, 'HOST')
        self.main_tab.addTab(self.stat_tab, 'STAT')
        self.main_tab.addTab(self.run_tab, 'RUN')
        self.main_tab.addTab(self.log_tab, 'LOG')
        self.main_tab.addTab(self.ai_tab, 'AI')

        # Generate the sub-tabs
        if self.network_scan_dic:
            self.gen_network_tab()

        if self.host_asset_dic:
            self.gen_asset_tab()

        self.gen_host_tab()
        self.gen_stat_tab()
        self.gen_run_tab()
        self.gen_log_tab()
        self.gen_ai_tab()

        # Show main window
        common_pyqt5.auto_resize(self)
        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
        self.setWindowTitle('batchRun ' + str(VERSION))
        self.setWindowIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/monitor.ico'))
        common_pyqt5.center_window(self)

        # Background log cleanup on startup.
        self._start_log_cleanup()

    def _on_main_tab_changed(self, index):
        """Lazy-load LOG tab data on first switch."""
        current_widget = self.main_tab.widget(index)

        if current_widget == self.log_tab and not self._log_tab_loaded:
            self._log_tab_loaded = True
            self.gen_log_tab_table_async()

    def _start_log_cleanup(self):
        """Run log cleanup in background thread on startup."""
        retention_days = getattr(config, 'log_retention_days', 0)

        if retention_days <= 0:
            return

        log_dir = str(config.db_path) + '/log'

        if not os.path.exists(log_dir):
            return

        self._cleanup_thread = threading.Thread(target=self._run_log_cleanup, args=(retention_days,), daemon=True)
        self._cleanup_thread.start()

    def _run_log_cleanup(self, days):
        """Background log cleanup worker."""
        sys.path.insert(0, str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/tools')

        try:
            import cleanup_log
            cleanup_log.cleanup_log(days=days)
        except Exception:
            pass

    def gen_menubar(self):
        """
        Generate menubar.
        """
        menubar = self.menuBar()

        # File
        export_network_table_action = QAction('Export network table', self)
        export_network_table_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/save.png'))
        export_network_table_action.triggered.connect(self.export_network_table)

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
            file_menu.addAction(export_network_table_action)

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

        # AI
        ai_cluster_analysis_action = QAction('Cluster Analysis', self)
        ai_cluster_analysis_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/trace.png'))
        ai_cluster_analysis_action.triggered.connect(self.cluster_analysis)

        ai_security_analysis_action = QAction('Security Analysis', self)
        ai_security_analysis_action.setIcon(QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/trace.png'))
        ai_security_analysis_action.triggered.connect(self.security_analysis)

        self.ai_debug_action = QAction('Debug', self)
        self.ai_debug_action.setCheckable(True)
        self.ai_debug_action.setChecked(False)

        ai_menu = menubar.addMenu('AI')
        ai_menu.addAction(ai_cluster_analysis_action)
        ai_menu.addAction(ai_security_analysis_action)
        ai_menu.addSeparator()
        ai_menu.addAction(self.ai_debug_action)

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
            self._diagram_ever_generated = False
            self.gen_network_tab()
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

# For network TAB (begin) #
    def gen_network_tab(self):
        """
        Generate the NETWORK tab on batchRun GUI, show network_scan.json and host.list informations.
        """
        if not self.network_tab.layout():
            # self.network_tab
            self.network_tab_qtree = QTreeWidget(self.network_tab)
            self.network_tab_qtree.itemDoubleClicked.connect(self.network_tab_qtree_double_clicked)
            self.network_tab_qtree.itemClicked.connect(self.highlight_in_diagram)

            self.network_tab_frame0 = QFrame(self.network_tab)
            self.network_tab_frame0.setFrameShadow(QFrame.Raised)
            self.network_tab_frame0.setFrameShape(QFrame.Box)

            self.network_tab_table = QTableWidget()

            self.network_tab_view = ZoomableGraphicsView()
            self.network_tab_scene = QGraphicsScene()
            self.network_tab_view.setScene(self.network_tab_scene)

            self.network_tab_right = QTabWidget(self.network_tab)
            self.network_tab_right.addTab(self.network_tab_table, 'Table')
            self.network_tab_right.addTab(self.network_tab_view, 'Diagram')
            self.network_tab_right.currentChanged.connect(self._on_right_tab_changed)

            # self.network_tab - Grid
            network_tab_grid = QGridLayout()

            network_tab_grid.addWidget(self.network_tab_qtree, 0, 0, 2, 1)
            network_tab_grid.addWidget(self.network_tab_frame0, 0, 1)
            network_tab_grid.addWidget(self.network_tab_right, 1, 1)

            network_tab_grid.setRowStretch(0, 1)
            network_tab_grid.setRowStretch(1, 20)

            network_tab_grid.setColumnStretch(0, 1)
            network_tab_grid.setColumnStretch(1, 5)

            self.network_tab.setLayout(network_tab_grid)

        # Generate sub-frames
        self.gen_network_tab_qtree()
        self.gen_network_tab_frame0()
        self.gen_network_tab_table()

    def gen_network_tab_qtree(self):
        # self.network_tab_qtree
        self.network_tab_qtree.setColumnCount(1)
        self.network_tab_qtree.setHeaderLabels(['     Zone  -  Network  - Ip', ])
        self.network_tab_qtree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.network_tab_qtree.header().setStretchLastSection(False)

        zone_list = list(self.network_scan_dic.keys())

        # Add items.
        for zone in zone_list:
            zone_item = QTreeWidgetItem(self.network_tab_qtree)
            zone_item.setText(0, zone)
            zone_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/Z.png'))

            for network in self.network_scan_dic[zone].keys():
                child_item = QTreeWidgetItem()
                child_item.setText(0, network)
                child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/N.png'))

                for host_ip in sorted(self.network_scan_dic[zone][network].keys(), key=_ip_sort_key):
                    sub_child_item = QTreeWidgetItem()
                    sub_child_item.setText(0, host_ip)
                    sub_child_item.setIcon(0, QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/H.png'))
                    child_item.addChild(sub_child_item)

                zone_item.addChild(child_item)

            self.network_tab_qtree.expandItem(zone_item)

    def network_tab_qtree_double_clicked(self, item, column):
        """
        Select double clicked zone/network on self.network_tab_frame0.
        """
        item_text = item.text(column)
        self.network_tab_host_line.setText('')

        for (i, qBox) in enumerate(self.network_tab_zone_combo.checkBoxList):
            if qBox.text() == 'ALL':
                self.network_tab_zone_combo.checkBoxList[i].setChecked(True)
            else:
                self.network_tab_zone_combo.checkBoxList[i].setChecked(False)

        for (i, qBox) in enumerate(self.network_tab_network_combo.checkBoxList):
            if qBox.text() == 'ALL':
                self.network_tab_network_combo.checkBoxList[i].setChecked(True)
            else:
                self.network_tab_network_combo.checkBoxList[i].setChecked(False)

        for (i, qBox) in enumerate(self.network_tab_group_combo.checkBoxList):
            if qBox.text() == 'ALL':
                self.network_tab_group_combo.checkBoxList[i].setChecked(True)
            else:
                self.network_tab_group_combo.checkBoxList[i].setChecked(False)

        if item_text:
            zone_list = []
            network_list = []

            for zone in self.network_scan_dic.keys():
                zone_list = zone_list + [zone] if zone not in zone_list else zone_list

                for network in self.network_scan_dic[zone].keys():
                    network_list = network_list + [network] if network not in network_list else network_list

            if item_text in zone_list:
                for (i, qBox) in enumerate(self.network_tab_zone_combo.checkBoxList):
                    if qBox.text() == item_text:
                        self.network_tab_zone_combo.checkBoxList[i].setChecked(True)
            elif item_text in network_list:
                for (i, qBox) in enumerate(self.network_tab_network_combo.checkBoxList):
                    if qBox.text() == item_text:
                        self.network_tab_network_combo.checkBoxList[i].setChecked(True)
            else:
                self.network_tab_host_line.setText(item_text)

            self.gen_network_tab_from_filters()

    def gen_network_tab_frame0(self):
        # self.network_tab_frame0
        if self.network_tab_frame0.layout():
            self.set_network_tab_zone_combo()
            self.set_network_tab_network_combo()
            self.set_network_tab_group_combo()
            return

        # "Zone" item.
        network_tab_zone_label = QLabel('Zone', self.network_tab_frame0)
        network_tab_zone_label.setStyleSheet("font-weight: bold;")
        network_tab_zone_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.network_tab_zone_combo = common_pyqt5.QComboCheckBox(self.network_tab_frame0)
        self.set_network_tab_zone_combo()
        self.network_tab_zone_combo.activated.connect(lambda: self.set_network_tab_network_combo())

        # "Network" item.
        network_tab_network_label = QLabel('Network', self.network_tab_frame0)
        network_tab_network_label.setStyleSheet("font-weight: bold;")
        network_tab_network_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.network_tab_network_combo = common_pyqt5.QComboCheckBox(self.network_tab_frame0)
        self.set_network_tab_network_combo()

        # "Group" item.
        network_tab_group_label = QLabel('Group', self.network_tab_frame0)
        network_tab_group_label.setStyleSheet("font-weight: bold;")
        network_tab_group_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.network_tab_group_combo = common_pyqt5.QComboCheckBox(self.network_tab_frame0)
        self.set_network_tab_group_combo()
        self.network_tab_group_combo.activated.connect(self.gen_network_tab_from_filters)

        # "Host" item.
        network_tab_host_label = QLabel('Host', self.network_tab_frame0)
        network_tab_host_label.setStyleSheet("font-weight: bold;")
        network_tab_host_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.network_tab_host_line = QLineEdit()
        self.network_tab_host_line.returnPressed.connect(self.gen_network_tab_from_filters)

        network_tab_host_line_completer = common_pyqt5.get_completer(self.completer_host_list)
        self.network_tab_host_line.setCompleter(network_tab_host_line_completer)

        # empty item.
        network_tab_empty_label = QLabel('', self.network_tab_frame0)

        # "Check" button.
        network_tab_check_button = QPushButton('Check', self.network_tab_frame0)
        network_tab_check_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        network_tab_check_button.clicked.connect(self.gen_network_tab_from_filters)

        # self.network_tab_frame0 - Grid
        network_tab_frame0_grid = QGridLayout()

        network_tab_frame0_grid.addWidget(network_tab_zone_label, 0, 0)
        network_tab_frame0_grid.addWidget(self.network_tab_zone_combo, 0, 1)
        network_tab_frame0_grid.addWidget(network_tab_network_label, 0, 2)
        network_tab_frame0_grid.addWidget(self.network_tab_network_combo, 0, 3)
        network_tab_frame0_grid.addWidget(network_tab_group_label, 0, 4)
        network_tab_frame0_grid.addWidget(self.network_tab_group_combo, 0, 5)
        network_tab_frame0_grid.addWidget(network_tab_host_label, 0, 6)
        network_tab_frame0_grid.addWidget(self.network_tab_host_line, 0, 7)
        network_tab_frame0_grid.addWidget(network_tab_empty_label, 0, 8)
        network_tab_frame0_grid.addWidget(network_tab_check_button, 0, 9)

        network_tab_frame0_grid.setColumnStretch(0, 2)
        network_tab_frame0_grid.setColumnStretch(1, 2)
        network_tab_frame0_grid.setColumnStretch(2, 2)
        network_tab_frame0_grid.setColumnStretch(3, 2)
        network_tab_frame0_grid.setColumnStretch(4, 2)
        network_tab_frame0_grid.setColumnStretch(5, 2)
        network_tab_frame0_grid.setColumnStretch(6, 2)
        network_tab_frame0_grid.setColumnStretch(7, 12)
        network_tab_frame0_grid.setColumnStretch(8, 1)
        network_tab_frame0_grid.setColumnStretch(9, 2)

        self.network_tab_frame0.setLayout(network_tab_frame0_grid)

    def set_network_tab_zone_combo(self, checked_zone_list=['ALL', ]):
        """
        Set (initialize) self.network_tab_zone_combo.
        """
        self.network_tab_zone_combo.clear()

        zone_list = copy.deepcopy(list(self.network_scan_dic.keys()))
        zone_list.sort()
        zone_list.insert(0, 'ALL')

        for zone in zone_list:
            self.network_tab_zone_combo.addCheckBoxItem(zone, update_width=True)

        # Set to checked status for checked_zone_list.
        for (i, qBox) in enumerate(self.network_tab_zone_combo.checkBoxList):
            if (qBox.text() in checked_zone_list) and (qBox.isChecked() is False):
                self.network_tab_zone_combo.checkBoxList[i].setChecked(True)

    def set_network_tab_network_combo(self, checked_network_list=['ALL', ]):
        """
        Set (initialize) self.network_tab_network_combo.
        """
        self.network_tab_network_combo.clear()

        specified_zone_list = self.network_tab_zone_combo.currentText().strip().split()
        network_list = []

        for zone in self.network_scan_dic.keys():
            if ('ALL' in specified_zone_list) or (zone in specified_zone_list):
                for network in self.network_scan_dic[zone].keys():
                    if network not in network_list:
                        network_list.append(network)

        network_list.sort()
        network_list.insert(0, 'ALL')

        for network in network_list:
            self.network_tab_network_combo.addCheckBoxItem(network, update_width=True)

        # Set to checked status for checked_network_list.
        for (i, qBox) in enumerate(self.network_tab_network_combo.checkBoxList):
            if (qBox.text() in checked_network_list) and (qBox.isChecked() is False):
                self.network_tab_network_combo.checkBoxList[i].setChecked(True)

    def set_network_tab_group_combo(self, checked_group_list=['ALL', ]):
        """
        Set (initialize) self.network_tab_group_combo.
        Collects all groups that appear in the network scan data.
        """
        self.network_tab_group_combo.clear()

        group_set = set()
        for zone in self.network_scan_dic.keys():
            for network in self.network_scan_dic[zone].keys():
                for host_ip in self.network_scan_dic[zone][network].keys():
                    if host_ip in self.host_group_relationship_dic:
                        for g in self.host_group_relationship_dic[host_ip]:
                            group_set.add(g)

        group_list = sorted(group_set)
        group_list.insert(0, 'ALL')

        for group in group_list:
            self.network_tab_group_combo.addCheckBoxItem(group, update_width=True)

        for (i, qBox) in enumerate(self.network_tab_group_combo.checkBoxList):
            if (qBox.text() in checked_group_list) and (qBox.isChecked() is False):
                self.network_tab_group_combo.checkBoxList[i].setChecked(True)

    def gen_network_tab_table(self):
        network_tab_table_dic = self.collect_network_tab_table_info()

        # self.network_tab_table
        self.network_tab_table.setShowGrid(True)
        self.network_tab_table.setSortingEnabled(True)
        self.network_tab_table.setColumnCount(0)
        self.network_tab_table_title_list = ['zone', 'network', 'host_ip', 'host_name', 'groups', 'packet', 'received', 'packet_loss', 'rtt_avg']
        self.network_tab_table.setColumnCount(len(self.network_tab_table_title_list))
        self.network_tab_table.setHorizontalHeaderLabels(self.network_tab_table_title_list)

        self.network_tab_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.network_tab_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.network_tab_table.setColumnWidth(2, 120)
        self.network_tab_table.setColumnWidth(3, 160)
        self.network_tab_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.network_tab_table.setColumnWidth(5, 80)
        self.network_tab_table.setColumnWidth(6, 80)
        self.network_tab_table.setColumnWidth(7, 120)
        self.network_tab_table.setColumnWidth(8, 100)

        # Fill self.network_tab_table items.
        host_line_num = 0

        for zone in network_tab_table_dic.keys():
            for network in network_tab_table_dic[zone].keys():
                for host_ip in sorted(network_tab_table_dic[zone][network].keys(), key=_ip_sort_key):
                    host_line_num += 1

        self.network_tab_table.setRowCount(0)
        self.network_tab_table.setRowCount(host_line_num)

        i = -1

        for zone in network_tab_table_dic.keys():
            for network in network_tab_table_dic[zone].keys():
                for host_ip in sorted(network_tab_table_dic[zone][network].keys(), key=_ip_sort_key):
                    i += 1
                    host_name = network_tab_table_dic[zone][network][host_ip]['host_name']
                    groups = network_tab_table_dic[zone][network][host_ip]['groups']
                    packet = network_tab_table_dic[zone][network][host_ip]['packet']
                    received = network_tab_table_dic[zone][network][host_ip]['received']
                    packet_loss = network_tab_table_dic[zone][network][host_ip]['packet_loss']
                    rtt_avg = str(network_tab_table_dic[zone][network][host_ip]['rtt_avg']) + ' ' + str(network_tab_table_dic[zone][network][host_ip]['rtt_unit'])

                    # Fill "zone" item.
                    j = 0
                    item = QTableWidgetItem(zone)
                    self.network_tab_table.setItem(i, j, item)

                    # Fill "network" item.
                    j += 1
                    item = QTableWidgetItem(network)
                    self.network_tab_table.setItem(i, j, item)

                    # Fill "host_ip" item.
                    j += 1
                    item = QTableWidgetItem(host_ip)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

                    # Fill "host_name" item.
                    j += 1
                    item = QTableWidgetItem(host_name)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

                    # Fill "groups" item.
                    j += 1
                    item = QTableWidgetItem(groups)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

                    # Fill "packet" item.
                    j += 1
                    item = QTableWidgetItem()
                    item.setData(Qt.DisplayRole, packet)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

                    # Fill "received" item.
                    j += 1
                    item = QTableWidgetItem()
                    item.setData(Qt.DisplayRole, received)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

                    # Fill "packet_loss" item.
                    j += 1
                    item = QTableWidgetItem(packet_loss)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

                    # Fill "rtt_avg" item.
                    j += 1
                    item = QTableWidgetItem(rtt_avg)

                    if not host_name:
                        item.setBackground(QBrush(Qt.red))

                    self.network_tab_table.setItem(i, j, item)

    def collect_network_tab_table_info(self):
        """
        Collect host info with specified zone/network/host.
        network_tab_table_dic = {zone: {network: {host_ip: {***}}},
                             }
        """
        network_tab_table_dic = {}
        specified_zone_list = self.network_tab_zone_combo.currentText().strip().split()
        specified_network_list = self.network_tab_network_combo.currentText().strip().split()
        specified_group_list = self.network_tab_group_combo.currentText().strip().split()
        specified_host_list = self.network_tab_host_line.text().strip().split()

        if specified_zone_list and specified_network_list:
            for zone in self.network_scan_dic.keys():
                if ('ALL' in specified_zone_list) or (zone in specified_zone_list):
                    network_tab_table_dic.setdefault(zone, {})

                    for network in self.network_scan_dic[zone].keys():
                        if ('ALL' in specified_network_list) or (network in specified_network_list):
                            network_tab_table_dic[zone].setdefault(network, {})

                            for host_ip in sorted(self.network_scan_dic[zone][network].keys(), key=_ip_sort_key):
                                # Group filter
                                if ('ALL' not in specified_group_list) and any(g for g in specified_group_list if g):
                                    host_groups = self.host_group_relationship_dic.get(host_ip, [])

                                    if not any(g in specified_group_list for g in host_groups):
                                        continue

                                if (not specified_host_list) or (host_ip in specified_host_list) or ((host_ip in self.host_list_class.host_ip_dic) and any(host_name in specified_host_list for host_name in self.host_list_class.host_ip_dic[host_ip]['host_name'])):
                                    network_tab_table_dic[zone][network][host_ip] = self.network_scan_dic[zone][network][host_ip]

                                    if host_ip in self.host_list_class.host_ip_dic.keys():
                                        network_tab_table_dic[zone][network][host_ip]['host_name'] = '  '.join(self.host_list_class.host_ip_dic[host_ip]['host_name'])

                                        if host_ip in self.host_group_relationship_dic.keys():
                                            network_tab_table_dic[zone][network][host_ip]['groups'] = '  '.join(self.host_group_relationship_dic[host_ip])
                                        else:
                                            network_tab_table_dic[zone][network][host_ip]['groups'] = ''
                                    else:
                                        network_tab_table_dic[zone][network][host_ip]['host_name'] = ''
                                        network_tab_table_dic[zone][network][host_ip]['groups'] = ''

        return network_tab_table_dic

    def _subnet_capacity(self, cidr):
        """
        Calculate max usable host IP count for a CIDR network.
        Formula: 2^(32 - prefix) - 2 (minus network and broadcast addresses).
        """
        try:
            prefix = int(cidr.split('/')[-1])

            if prefix >= 31:
                return 1 if prefix == 31 else 0

            return (1 << (32 - prefix)) - 2
        except (ValueError, IndexError):
            return 0

    def gen_network_tab_from_filters(self):
        """
        Regenerate both table and diagram based on current filter settings.
        """
        self.gen_network_tab_table()

        if self._diagram_ever_generated:
            filter_dic = self.collect_network_tab_table_info()
            self.gen_network_tab_diagram(filter_dic)

    def gen_network_tab_diagram(self, filter_dic=None):
        """
        Build the vector diagram from self.network_scan_dic.
        If filter_dic is provided, only show entities present in it.
        Zones use flow layout: small zones share rows, large zones get their own row.
        Network rects and zone rects are draggable.
        When group filter is active, IPs not in selected groups are shown gray.
        """
        self.network_tab_scene.clear()
        self.network_tab_diagram_items = {}
        self.network_tab_highlighted_items = []

        IP_W, IP_H = 60, 18
        IP_PAD = 2
        NET_PAD = 12
        NET_TITLE_H = 20
        ZONE_PAD = 20
        ZONE_TITLE_H = 24
        ZONE_GAP = 20
        NET_GAP = 15
        MAX_ZONE_ROW_WIDTH = 4000

        x_offset = 50
        y_offset = 30

        specified_group_list = self.network_tab_group_combo.currentText().strip().split()
        group_filter_active = ('ALL' not in specified_group_list) and bool([g for g in specified_group_list if g])

        zone_list = sorted(self.network_scan_dic.keys())

        # Phase 1: compute zone sizes and network layouts without rendering
        zone_layouts = []

        for zone in zone_list:
            if filter_dic and zone not in filter_dic:
                continue

            network_list = sorted(self.network_scan_dic[zone].keys())

            if filter_dic:
                network_list = [n for n in network_list if n in filter_dic[zone]]

            if not network_list:
                continue

            net_layouts = []
            net_x_cursor = 0
            net_row_y = 0
            cur_row_max_h = 0
            max_row_width = 0

            for network in network_list:
                ip_dict = {ip: dict(info) for ip, info in self.network_scan_dic[zone][network].items()}

                if group_filter_active:
                    # Show all IPs in matching zones/networks, mark group membership
                    for ip in ip_dict:
                        host_groups = self.host_group_relationship_dic.get(ip, [])
                        ip_dict[ip]['_in_group'] = any(g in specified_group_list for g in host_groups)
                else:
                    if filter_dic:
                        ip_dict = {ip: info for ip, info in ip_dict.items()
                                   if ip in filter_dic[zone][network]}

                    for ip in ip_dict:
                        ip_dict[ip]['_in_group'] = True

                ip_count = len(ip_dict)
                active_count = sum(1 for info in ip_dict.values() if info.get('connectivity', False))
                total_capacity = self._subnet_capacity(network)

                cols = max(1, int(math.ceil(math.sqrt(ip_count))))
                rows = max(1, int(math.ceil(ip_count / cols)))

                net_w = NET_PAD * 2 + cols * (IP_W + IP_PAD) - IP_PAD
                net_h = NET_PAD * 2 + NET_TITLE_H + rows * (IP_H + IP_PAD) - IP_PAD

                # Ensure minimum width for title text
                title_text = str(network) + ' (' + str(active_count) + '/' + str(total_capacity) + ')'
                min_title_w = len(title_text) * 9 + 10
                net_w = max(net_w, min_title_w)

                # Wrap networks within zone
                if net_x_cursor + net_w > MAX_ZONE_ROW_WIDTH and net_x_cursor > 0:
                    max_row_width = max(max_row_width, net_x_cursor)
                    net_row_y += cur_row_max_h + NET_GAP
                    net_x_cursor = 0
                    cur_row_max_h = 0

                ip_list = sorted(ip_dict.items(), key=lambda x: _ip_sort_key(x[0]))
                net_layouts.append((network, net_w, net_h, net_x_cursor, net_row_y, ip_list, cols, active_count, total_capacity))
                net_x_cursor += net_w + NET_GAP
                cur_row_max_h = max(cur_row_max_h, net_h)

            max_row_width = max(max_row_width, net_x_cursor)
            zone_w = max_row_width - NET_GAP + ZONE_PAD * 2
            zone_h = ZONE_PAD * 2 + ZONE_TITLE_H + net_row_y + cur_row_max_h
            zone_layouts.append((zone, zone_w, zone_h, net_layouts))

        # Phase 2: flow layout for zones and render
        zone_row_x = x_offset
        zone_row_y = y_offset
        zone_row_max_h = 0

        for zone, zone_w, zone_h, net_layouts in zone_layouts:
            if zone_row_x + zone_w > x_offset + MAX_ZONE_ROW_WIDTH and zone_row_x > x_offset:
                zone_row_x = x_offset
                zone_row_y += zone_row_max_h + ZONE_GAP
                zone_row_max_h = 0

            zone_x = zone_row_x
            zone_y = zone_row_y

            # Create zone rect at final position
            zone_rect = ZoneRectItem(zone)
            zone_rect._recalcing = True  # Suppress recalcBounds during initial placement
            zone_rect.setPos(zone_x, zone_y)
            zone_rect.setRect(0, 0, zone_w, zone_h)
            self.network_tab_scene.addItem(zone_rect)

            key = 'ZONE::' + str(zone)
            self.network_tab_diagram_items[key] = zone_rect

            for network, net_w, net_h, net_off_x, net_off_y, ip_list, cols, active_count, total_count in net_layouts:
                # Network position relative to zone
                net_local_x = ZONE_PAD + net_off_x
                net_local_y = ZONE_PAD + ZONE_TITLE_H + net_off_y

                # Create network rect as child of zone
                net_rect = NetworkRectItem(network, active_count, total_count, zone_rect)
                net_rect.setPos(net_local_x, net_local_y)
                net_rect.setRect(0, 0, net_w, net_h)

                key = 'NET::' + str(zone) + '::' + str(network)
                self.network_tab_diagram_items[key] = net_rect

                for idx, (ip, info) in enumerate(ip_list):
                    row = idx // cols
                    col = idx % cols

                    ip_x = NET_PAD + col * (IP_W + IP_PAD)
                    ip_y = NET_PAD + NET_TITLE_H + row * (IP_H + IP_PAD)

                    if 'host_name' not in info:
                        if ip in self.host_list_class.host_ip_dic:
                            info['host_name'] = '  '.join(self.host_list_class.host_ip_dic[ip]['host_name'])
                        else:
                            info['host_name'] = ''
                    if 'groups' not in info:
                        if ip in self.host_group_relationship_dic:
                            info['groups'] = '  '.join(self.host_group_relationship_dic[ip])
                        else:
                            info['groups'] = ''
                    # Enrich with host_info data for tooltip
                    if ip in self.host_info_dic:
                        for k in ('server_type', 'os', 'cpu_architecture', 'cpu_thread',
                                  'cpu_model', 'cpu_frequency', 'cpu_frequency_unit',
                                  'mem_size', 'mem_size_unit', 'swap_size', 'swap_size_unit'):
                            if k in self.host_info_dic[ip]:
                                info[k] = self.host_info_dic[ip][k]

                    ip_rect = IPRectItem(ip, info, net_rect)
                    ip_rect.setRect(ip_x, ip_y, IP_W, IP_H)

                    if not info.get('_in_group', True):
                        ip_rect.setBrush(QBrush(QColor(70, 70, 70)))

                    key = 'IP::' + str(zone) + '::' + str(network) + '::' + str(ip)
                    self.network_tab_diagram_items[key] = ip_rect

            # Enable recalcBounds and do initial bounds calculation
            zone_rect._recalcing = False
            zone_rect.recalcBounds()

            zone_row_x += zone_w + ZONE_GAP
            zone_row_max_h = max(zone_row_max_h, zone_h)

        self.network_tab_scene.setSceneRect(self.network_tab_scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))
        self.network_tab_view.fitInView(self.network_tab_scene.sceneRect(), Qt.KeepAspectRatio)

    def highlight_in_diagram(self, item, column=0):
        """
        Highlight the entity corresponding to the clicked tree item in the diagram.
        """
        if not self._diagram_ever_generated:
            return

        self.clear_diagram_highlights()

        entity_text = item.text(column)
        parent = item.parent()

        if parent is None:
            key = 'ZONE::' + str(entity_text)
        elif parent.parent() is None:
            zone = parent.text(column)
            key = 'NET::' + str(zone) + '::' + str(entity_text)
        else:
            network = parent.text(column)
            zone = parent.parent().text(column)
            key = 'IP::' + str(zone) + '::' + str(network) + '::' + str(entity_text)

        if key in self.network_tab_diagram_items:
            gitem = self.network_tab_diagram_items[key]
            self._apply_highlight(gitem)
            self.network_tab_highlighted_items.append(gitem)
            self.network_tab_view.centerOn(gitem)

    def _apply_highlight(self, graphics_item):
        """
        Apply bright highlight border to a graphics item.
        """
        if isinstance(graphics_item, ZoneRectItem):
            pen = QPen(QColor(255, 255, 0), 4, Qt.DashLine)
        elif isinstance(graphics_item, NetworkRectItem):
            pen = QPen(QColor(255, 255, 0), 4)
        else:
            pen = QPen(QColor(255, 255, 0), 3)
        graphics_item.setPen(pen)
        graphics_item.setZValue(100)

    def clear_diagram_highlights(self):
        """
        Remove highlights from all previously highlighted items.
        """
        for gitem in self.network_tab_highlighted_items:
            if isinstance(gitem, ZoneRectItem):
                gitem.setPen(QPen(QColor(255, 180, 50), 2, Qt.DashLine))
            elif isinstance(gitem, NetworkRectItem):
                gitem.setPen(QPen(QColor(140, 160, 200), 2))
            else:
                gitem.setPen(QPen(QColor(150, 150, 150), 1))
            gitem.setZValue(0)
        self.network_tab_highlighted_items = []

    def _on_right_tab_changed(self, index):
        """
        Lazy-generate the diagram when the user switches to the diagram tab.
        """
        if index == 1 and not self._diagram_ever_generated:
            filter_dic = self.collect_network_tab_table_info()
            self.gen_network_tab_diagram(filter_dic)
            self._diagram_ever_generated = True

# For network TAB (end) #

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
            other_keys = [k for k in asset_tab_table_dic[first_asset_host_ip].keys()
                          if k not in ('host_ip', 'host_name', 'groups')]
            self.asset_tab_table_title_list = ['host_ip', 'host_name', 'groups'] + other_keys
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
                if host_ip_attribute in ('host_ip', 'host_name', 'groups'):
                    continue

                j += 1
                item_string = asset_tab_table_dic[host_ip][host_ip_attribute]

                if isinstance(item_string, list):
                    item_string = '  '.join(str(x) for x in item_string)
                elif not isinstance(item_string, str):
                    item_string = str(item_string)

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
        if self.main_tab.indexOf(self.asset_tab) == -1:
            self.main_tab.addTab(self.asset_tab, 'ASSET')

        self.gen_asset_tab()

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
            self.stat_tab_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.stat_tab_table.itemClicked.connect(self.stat_tab_check_click)
            self.stat_tab_table.itemDoubleClicked.connect(self.on_table_double_click)

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

        # statistic web
        self.web_server = WebServer()

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

    def _find_latest_host_stat_file(self):
        """Find the latest host_stat.json: try top-level symlink first, then scan date/time subdirs."""
        host_stat_dir = str(config.db_path) + '/host_stat'
        top_file = host_stat_dir + '/host_stat.json'

        if os.path.exists(top_file):
            return top_file

        if not os.path.isdir(host_stat_dir):
            return ''

        date_dirs = sorted([d for d in os.listdir(host_stat_dir) if re.match(r'^\d{8}$', d)], reverse=True)

        for date_dir in date_dirs:
            date_path = os.path.join(host_stat_dir, date_dir)

            if not os.path.isdir(date_path):
                continue

            time_dirs = sorted([t for t in os.listdir(date_path) if re.match(r'^\d{6}$', t)], reverse=True)

            for time_dir in time_dirs:
                stat_file = os.path.join(date_path, time_dir, 'host_stat.json')

                if os.path.exists(stat_file):
                    return stat_file

        return ''

    def stat_to_asset_tab(self):
        """
        Get selected host_ip list, and jump to ASSET tab, generate self.asset_tab_table.
        """
        if self.main_tab.indexOf(self.asset_tab) == -1:
            self.main_tab.addTab(self.asset_tab, 'ASSET')

        self.gen_asset_tab()

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

    def on_table_double_click(self, item=None):
        if item is None:
            return

        row = item.row()
        ip_item = self.stat_tab_table.item(row, 0).text().strip()

        if ip_item:
            data_path = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/web'
            self.web_server.open_url_in_firefox(data_path, ip_item)
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

        # Generate sub-frames (table loaded lazily on first tab switch)
        self.gen_log_tab_frame0()
        self._log_tab_loaded = False
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
        self.log_tab_info_line.returnPressed.connect(self.gen_log_tab_table_async)

        # empty item.
        log_tab_empty_label = QLabel('', self.log_tab_frame0)

        # "Search" button.
        log_tab_search_button = QPushButton('Search', self.log_tab_frame0)
        log_tab_search_button.setStyleSheet('''QPushButton:hover{background:rgb(0, 85, 255);}''')
        log_tab_search_button.clicked.connect(self.gen_log_tab_table_async)

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

    def gen_log_tab_table_async(self):
        """Load log data in background thread to avoid blocking UI."""
        self.log_tab_table.setRowCount(0)
        self.log_tab_table.setColumnCount(1)
        self.log_tab_table.setHorizontalHeaderLabels([''])
        self.log_tab_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        loading_item = QTableWidgetItem('Loading ...')
        loading_item.setTextAlignment(Qt.AlignCenter)
        self.log_tab_table.setRowCount(1)
        self.log_tab_table.setItem(0, 0, loading_item)

        self._log_load_thread = threading.Thread(target=self._collect_log_data_background, daemon=True)
        self._log_load_thread.start()

    def _collect_log_data_background(self):
        """Collect log data in background, then update table in main thread."""
        self.collect_log_tab_table_info()
        QApplication.instance().postEvent(self, LogDataReadyEvent())

    def customEvent(self, event):
        if isinstance(event, LogDataReadyEvent):
            self.gen_log_tab_table()

    def gen_log_tab_table(self):
        """
        Generate self.log_tab_tale.
        """
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

        log_icon = QIcon(str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/data/pictures/log.png')

        for i, log_dic in enumerate(self.log_dic_list):
            self.log_tab_table.setItem(i, 0, QTableWidgetItem(log_dic['time']))
            self.log_tab_table.setItem(i, 1, QTableWidgetItem(log_dic['user']))
            self.log_tab_table.setItem(i, 2, QTableWidgetItem(log_dic['login_user']))
            self.log_tab_table.setItem(i, 3, QTableWidgetItem(log_dic['command']))
            item = QTableWidgetItem()
            item.setIcon(log_icon)
            self.log_tab_table.setItem(i, 4, item)

    def collect_log_tab_table_info(self, max_records=5000):
        """
        Collect history records with specified user/begin_date/end_date.
        Reads files from tail for efficiency, stops early when enough records collected.
        """
        self.log_dic_list = []
        specified_user_list = self.log_tab_user_combo.currentText().strip().split()
        specified_begin_date = self.log_tab_begin_date_edit.date().toString('yyyyMMdd')
        specified_end_date = self.log_tab_end_date_edit.date().toString('yyyyMMdd')
        specified_info = self.log_tab_info_line.text().strip()

        if 'ALL' in specified_user_list:
            specified_user_list = self.get_log_user_list()

        collected = 0

        for specified_user in specified_user_list:
            user_command_history_file = str(config.db_path) + '/log/' + str(specified_user) + '/command.his'

            if not os.path.exists(user_command_history_file):
                continue

            try:
                with open(user_command_history_file, 'rb') as f:
                    f.seek(0, 2)
                    file_size = f.tell()

                    if file_size == 0:
                        continue

                    # Read from end in chunks.
                    chunk_size = 1024 * 1024
                    remainder = b''
                    position = file_size
                    stop_user = False

                    while position > 0 and not stop_user:
                        read_size = min(chunk_size, position)
                        position -= read_size
                        f.seek(position)
                        chunk = f.read(read_size) + remainder
                        lines = chunk.split(b'\n')
                        remainder = lines[0]

                        for line in reversed(lines[1:]):
                            if not line.strip():
                                continue

                            try:
                                line_dic = json.loads(line)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                continue

                            record_date = line_dic.get('date', '')

                            if record_date < specified_begin_date:
                                stop_user = True
                                break

                            if record_date > specified_end_date:
                                continue

                            if specified_info and not re.search(specified_info, line_dic.get('command', '')):
                                continue

                            fmt_time = datetime.datetime.strptime(
                                str(record_date) + str(line_dic['time']), '%Y%m%d%H%M%S'
                            ).strftime('%Y-%m-%d %H:%M:%S')

                            self.log_dic_list.append({
                                'time': fmt_time,
                                'user': line_dic.get('user', ''),
                                'login_user': line_dic.get('login_user', ''),
                                'command': line_dic.get('command', ''),
                                'log': line_dic.get('log', '')
                            })
                            collected += 1

                            if collected >= max_records:
                                stop_user = True
                                break

                    # Process remainder (first line of file).
                    if remainder and not stop_user and collected < max_records:
                        try:
                            line_dic = json.loads(remainder)
                            record_date = line_dic.get('date', '')

                            if specified_begin_date <= record_date <= specified_end_date:
                                if (not specified_info) or re.search(specified_info, line_dic.get('command', '')):
                                    fmt_time = datetime.datetime.strptime(
                                        str(record_date) + str(line_dic['time']), '%Y%m%d%H%M%S'
                                    ).strftime('%Y-%m-%d %H:%M:%S')
                                    self.log_dic_list.append({
                                        'time': fmt_time,
                                        'user': line_dic.get('user', ''),
                                        'login_user': line_dic.get('login_user', ''),
                                        'command': line_dic.get('command', ''),
                                        'log': line_dic.get('log', '')
                                    })
                        except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
                            pass
            except (OSError, PermissionError):
                continue

            if collected >= max_records:
                break

        self.log_dic_list.sort(key=lambda x: x['time'], reverse=True)

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
    def export_network_table(self):
        self.export_table('network', self.network_tab_table, self.network_tab_table_title_list)

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

# For AI TAB (begin) #
    def gen_ai_tab(self):
        """
        Generate the AI helpdesk tab.
        """
        self.ai_configured = False
        self.ai_thread = None

        if hasattr(config, 'ai_api_base_url') and config.ai_api_base_url and hasattr(config, 'ai_api_key') and config.ai_api_key and hasattr(config, 'ai_model_name') and config.ai_model_name:
            self.ai_configured = True

        # Chat display area.
        self.ai_tab_chat_text = QTextEdit(self.ai_tab)
        self.ai_tab_chat_text.setReadOnly(True)
        self._create_chat_avatars()

        if not self.ai_configured:
            self.ai_tab_chat_text.setHtml('<p>AI helpdesk is not configured.</p><p>Please set <b>ai_api_base_url</b>, <b>ai_api_key</b>, and <b>ai_model_name</b> in config.py.</p>')

        # Input area (multi-line, Enter sends, Shift+Enter for newline).
        self.ai_tab_input = AiInputBox(self.ai_tab)
        self.ai_tab_input.setPlaceholderText('Ask AI about cluster status, host health, security, assets ... (Enter to send, Shift+Enter for newline)')
        self.ai_tab_input.setFixedHeight(60)
        self.ai_tab_input.send_requested.connect(self.ai_tab_send_message)

        if not self.ai_configured:
            self.ai_tab_input.setEnabled(False)

        # Buttons (stacked vertically, matching input height).
        ai_tab_send_button = QPushButton('Send', self.ai_tab)
        ai_tab_send_button.setFixedHeight(28)
        ai_tab_send_button.clicked.connect(self.ai_tab_send_message)

        ai_tab_clear_button = QPushButton('Clear', self.ai_tab)
        ai_tab_clear_button.setFixedHeight(28)
        ai_tab_clear_button.clicked.connect(self.ai_tab_clear_chat)

        button_layout = QVBoxLayout()
        button_layout.addWidget(ai_tab_send_button)
        button_layout.addWidget(ai_tab_clear_button)
        button_layout.setSpacing(4)

        # Feedback bar (hidden by default, shown after AI response).
        self.ai_feedback_widget = QWidget(self.ai_tab)
        feedback_layout = QHBoxLayout(self.ai_feedback_widget)
        feedback_layout.setContentsMargins(0, 2, 0, 2)
        feedback_layout.setSpacing(6)

        feedback_label = QLabel('Was this helpful?')
        feedback_label.setStyleSheet('color: #888; font-size: 11px;')
        feedback_layout.addWidget(feedback_label)

        self.ai_feedback_solved_btn = QPushButton('Solved')
        self.ai_feedback_solved_btn.setFixedSize(60, 22)
        self.ai_feedback_solved_btn.setStyleSheet('font-size: 11px;')
        self.ai_feedback_solved_btn.clicked.connect(lambda: self._ai_tab_user_feedback('solved'))
        feedback_layout.addWidget(self.ai_feedback_solved_btn)

        self.ai_feedback_unsolved_btn = QPushButton('Unsolved')
        self.ai_feedback_unsolved_btn.setFixedSize(70, 22)
        self.ai_feedback_unsolved_btn.setStyleSheet('font-size: 11px;')
        self.ai_feedback_unsolved_btn.clicked.connect(lambda: self._ai_tab_user_feedback('unsolved'))
        feedback_layout.addWidget(self.ai_feedback_unsolved_btn)

        feedback_layout.addStretch()
        self.ai_feedback_widget.hide()

        # Layout.
        ai_tab_grid = QGridLayout()
        ai_tab_grid.addWidget(self.ai_tab_chat_text, 0, 0, 1, 2)
        ai_tab_grid.addWidget(self.ai_feedback_widget, 1, 0, 1, 2)
        ai_tab_grid.addWidget(self.ai_tab_input, 2, 0)
        ai_tab_grid.addLayout(button_layout, 2, 1)
        ai_tab_grid.setColumnStretch(0, 10)
        ai_tab_grid.setColumnStretch(1, 1)
        self.ai_tab.setLayout(ai_tab_grid)

        # Init conversation history.
        system_prompt = common_ai.SYSTEM_PROMPT.format(db_path=config.db_path, host_list=config.host_list)
        self.ai_messages = [{"role": "system", "content": system_prompt + f"\n\nCurrent user: {CURRENT_USER}"}]

        # Load skills.
        skills_dir = os.path.join(os.environ.get('BATCH_RUN_INSTALL_PATH', '.'), 'config', 'skills')
        self.ai_skills = common_ai.load_skills(skills_dir)

        # Init AI log database.
        self.ai_log_db_file = common_ai_log.init_ai_log_db(config.db_path)

    def _create_chat_avatars(self):
        """Create user (person) and AI (robot) avatar icons with QPainter."""
        size = 32
        doc = self.ai_tab_chat_text.document()

        clip = QPainterPath()
        clip.addEllipse(0, 0, size, size)

        # User avatar: blue circle, white person silhouette.
        user_pm = QPixmap(size, size)
        user_pm.fill(Qt.transparent)
        p = QPainter(user_pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setClipPath(clip)
        p.fillRect(0, 0, size, size, QColor('#5DADE2'))
        p.setBrush(QColor('#FFFFFF'))
        p.setPen(Qt.NoPen)
        p.drawEllipse(10, 3, 12, 12)
        p.drawEllipse(4, 17, 24, 22)
        p.end()

        # AI avatar: green circle, white robot face.
        ai_pm = QPixmap(size, size)
        ai_pm.fill(Qt.transparent)
        p = QPainter(ai_pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setClipPath(clip)
        p.fillRect(0, 0, size, size, QColor('#27AE60'))
        p.setBrush(QColor('#FFFFFF'))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(6, 7, 20, 14, 3, 3)
        p.setBrush(QColor('#27AE60'))
        p.drawRoundedRect(9, 10, 5, 5, 1, 1)
        p.drawRoundedRect(18, 10, 5, 5, 1, 1)
        p.drawRect(11, 17, 10, 2)
        p.setPen(QPen(QColor('#FFFFFF'), 2))
        p.drawLine(16, 7, 16, 3)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor('#FFFFFF'))
        p.drawEllipse(14, 0, 4, 4)
        p.drawRoundedRect(9, 23, 14, 7, 2, 2)
        p.end()

        doc.addResource(2, QUrl("user_avatar"), user_pm)
        doc.addResource(2, QUrl("ai_avatar"), ai_pm)

    def ai_tab_send_message(self):
        """Send user message to AI and start streaming response."""
        if not self.ai_configured:
            return

        user_text = self.ai_tab_input.toPlainText().strip()

        if not user_text:
            return

        if self.ai_thread and self.ai_thread.isRunning():
            return

        self.ai_feedback_widget.hide()

        # Display user message (right-aligned dark blue bubble with avatar).
        user_html = user_text.replace('\n', '<br>')
        self.ai_tab_chat_text.append(
            f'<table width="100%" cellspacing="0" cellpadding="0"><tr>'
            f'<td width="15%"></td>'
            f'<td style="background-color:#1B4F72; color:#D5D8DC; padding:10px 14px; -qt-block-indent:0;">'
            f'{user_html}</td>'
            f'<td width="42" valign="top" style="padding:2px 0 0 6px;">'
            f'<img src="user_avatar" width="32" height="32"></td>'
            f'</tr></table>'
        )
        self.ai_tab_input.clear()

        # Track session for AI log database.
        self._ai_send_time = time.time()
        self._current_ai_session_id = common_ai_log.gen_session_id()
        self._current_ai_question = user_text
        self._current_ai_tool_calls = []

        # Add to messages.
        self.ai_messages.append({"role": "user", "content": user_text})

        # Trim context if too long (keep system prompt + last 30 messages).
        if len(self.ai_messages) > 40:
            self.ai_messages = [self.ai_messages[0]] + self.ai_messages[-30:]

        # Get dangerous commands config.
        dangerous_commands = config.ai_dangerous_commands if hasattr(config, 'ai_dangerous_commands') and config.ai_dangerous_commands else common_ai.DEFAULT_DANGEROUS_COMMANDS

        # Insert AI block with animated "Thinking..." placeholder.
        self._ai_tab_start_ai_block()

        # Start AI thread.
        self.ai_thread = common_ai.AiChatThread(
            api_base_url=config.ai_api_base_url,
            api_key=config.ai_api_key,
            model_name=config.ai_model_name,
            messages=self.ai_messages,
            dangerous_commands=dangerous_commands,
            skills=self.ai_skills,
            debug=self.ai_debug_action.isChecked()
        )
        self.ai_thread.token_received.connect(self.ai_tab_on_token)
        self.ai_thread.tool_call_start.connect(self.ai_tab_on_tool_start)
        self.ai_thread.tool_call_result.connect(self.ai_tab_on_tool_result)
        self.ai_thread.finished_signal.connect(self.ai_tab_on_finished)
        self.ai_thread.error_signal.connect(self.ai_tab_on_error)
        self.ai_thread.confirm_requested.connect(self.ai_handle_confirm_request)
        self.ai_thread.status_signal.connect(self.ai_tab_on_status)
        self.ai_thread.sources_signal.connect(self.ai_tab_on_sources)
        self._ai_sources = {}
        self.ai_thread.start()

    def _ai_tab_start_ai_block(self):
        """Insert robot avatar with animated 'Thinking...' placeholder, set block format for streaming."""
        cursor = self.ai_tab_chat_text.textCursor()
        cursor.movePosition(cursor.End)

        table_fmt = QTextTableFormat()
        table_fmt.setBorder(0)
        table_fmt.setCellPadding(6)
        table_fmt.setCellSpacing(0)
        table_fmt.setTopMargin(6)
        table_fmt.setBottomMargin(4)
        table_fmt.setRightMargin(80)
        table_fmt.setColumnWidthConstraints([
            QTextLength(QTextLength.FixedLength, 42),
            QTextLength(QTextLength.PercentageLength, 100),
        ])
        table = cursor.insertTable(1, 2, table_fmt)

        # Left cell: avatar.
        avatar_cursor = table.cellAt(0, 0).firstCursorPosition()
        img_fmt = QTextImageFormat()
        img_fmt.setName("ai_avatar")
        img_fmt.setWidth(32)
        img_fmt.setHeight(32)
        avatar_cursor.insertImage(img_fmt)

        # Right cell: dark gray background message area.
        self._ai_msg_cell = table.cellAt(0, 1)
        cell_fmt = self._ai_msg_cell.format()
        cell_fmt.setBackground(QColor('#2D2D30'))
        self._ai_msg_cell.setFormat(cell_fmt)

        cursor = self._ai_msg_cell.firstCursorPosition()

        # Animated status placeholder in gray italic.
        self._ai_thinking_pos = cursor.position()
        self._ai_thinking_fmt = QTextCharFormat()
        self._ai_thinking_fmt.setForeground(QColor('#999999'))
        self._ai_thinking_fmt.setFontItalic(True)
        self._ai_status_base = 'Thinking'
        cursor.insertText('Thinking.', self._ai_thinking_fmt)
        self._ai_first_token = True
        self._ai_thinking_dots = 1

        # Start dot animation timer.
        if not hasattr(self, '_ai_thinking_timer'):
            self._ai_thinking_timer = QTimer(self)
            self._ai_thinking_timer.timeout.connect(self._ai_tab_animate_thinking)

        self._ai_thinking_timer.start(500)

        # Normal text format for streaming content.
        self._ai_text_fmt = QTextCharFormat()
        self._ai_text_fmt.setForeground(QColor('#D5D8DC'))

        self.ai_tab_chat_text.setTextCursor(cursor)
        self.ai_tab_chat_text.ensureCursorVisible()

    def _ai_frame_end_position(self):
        """Return the last valid cursor position inside the current AI message cell."""
        if hasattr(self, '_ai_msg_cell') and self._ai_msg_cell:
            return self._ai_msg_cell.lastCursorPosition().position()

        return self.ai_tab_chat_text.document().characterCount() - 1

    def _ai_tab_animate_thinking(self):
        """Cycle dots on status text: Thinking. -> Thinking.. -> Thinking..."""
        if not self._ai_first_token:
            self._ai_thinking_timer.stop()
            return

        self._ai_thinking_dots = (self._ai_thinking_dots % 3) + 1
        text = self._ai_status_base + '.' * self._ai_thinking_dots

        doc_length = self.ai_tab_chat_text.document().characterCount()
        end_pos = self._ai_frame_end_position()

        if self._ai_thinking_pos >= doc_length or end_pos >= doc_length:
            self._ai_thinking_timer.stop()
            return

        cursor = self.ai_tab_chat_text.textCursor()
        cursor.setPosition(self._ai_thinking_pos)
        cursor.setPosition(end_pos, cursor.KeepAnchor)
        cursor.insertText(text, self._ai_thinking_fmt)
        self.ai_tab_chat_text.setTextCursor(cursor)
        self.ai_tab_chat_text.ensureCursorVisible()

    def _ai_tab_remove_thinking(self):
        """Remove 'Thinking...' placeholder and stop animation."""
        if not self._ai_first_token:
            return

        self._ai_first_token = False

        if hasattr(self, '_ai_thinking_timer'):
            self._ai_thinking_timer.stop()

        doc_length = self.ai_tab_chat_text.document().characterCount()
        end_pos = self._ai_frame_end_position()

        if self._ai_thinking_pos >= doc_length or end_pos >= doc_length:
            return

        cursor = self.ai_tab_chat_text.textCursor()
        cursor.setPosition(self._ai_thinking_pos)
        cursor.setPosition(end_pos, cursor.KeepAnchor)
        cursor.removeSelectedText()
        self.ai_tab_chat_text.setTextCursor(cursor)

    def ai_tab_on_token(self, token):
        """Append a single token to the chat display (streaming)."""
        self._ai_tab_remove_thinking()
        cursor = self._ai_msg_cell.lastCursorPosition() if hasattr(self, '_ai_msg_cell') and self._ai_msg_cell else self.ai_tab_chat_text.textCursor()
        cursor.insertText(token, self._ai_text_fmt)
        self.ai_tab_chat_text.setTextCursor(cursor)
        self.ai_tab_chat_text.ensureCursorVisible()

    def ai_tab_on_status(self, status):
        """Update the animated status text with a new phase description."""
        self._ai_status_base = status
        self._ai_thinking_dots = 0
        self._ai_tab_animate_thinking()

    def ai_tab_on_tool_start(self, tool_name, description):
        """Tool call started - update status text to show what's being executed."""
        self._ai_status_base = description
        self._ai_thinking_dots = 0
        self._ai_tab_animate_thinking()

        self._current_ai_tool_calls.append({'name': tool_name, 'args': description, 'result': ''})

    def ai_tab_on_tool_result(self, tool_name, result):
        """Tool call finished - start a new AI block for the response."""
        if self._current_ai_tool_calls:
            self._current_ai_tool_calls[-1]['result'] = result[:1000]

        self._ai_tab_start_ai_block()

    def ai_tab_on_sources(self, sources):
        """Store sources dict emitted by AiChatThread."""
        self._ai_sources = sources

    def _ai_tab_render_sources(self, skills):
        """Append a sources block at the bottom of the current AI message cell."""
        if not hasattr(self, '_ai_msg_cell') or not self._ai_msg_cell:
            return

        cursor = self._ai_msg_cell.lastCursorPosition()

        cursor.insertBlock()
        sep_fmt = QTextCharFormat()
        sep_fmt.setForeground(QColor('#AAAAAA'))
        sep_fmt.setFontPointSize(8)
        cursor.insertText('─' * 40, sep_fmt)

        cursor.insertBlock()
        label_fmt = QTextCharFormat()
        label_fmt.setForeground(QColor('#666666'))
        label_fmt.setFontPointSize(9)
        label_fmt.setFontItalic(True)
        cursor.insertText('Sources:', label_fmt)

        item_fmt = QTextCharFormat()
        item_fmt.setForeground(QColor('#888888'))
        item_fmt.setFontPointSize(8)
        item_fmt.setFontItalic(True)

        for skill_name in skills:
            cursor.insertBlock()
            cursor.insertText(f'  · Skill: {skill_name}', item_fmt)

        self.ai_tab_chat_text.setTextCursor(cursor)

    def ai_tab_on_finished(self):
        """Called when AI response is complete."""
        # Render sources block if any skills were used.
        skills = self._ai_sources.get('skills', []) if self._ai_sources else []

        if skills:
            self._ai_tab_render_sources(skills)

        # Append total elapsed time.
        if hasattr(self, '_ai_send_time') and self._ai_send_time:
            elapsed = time.time() - self._ai_send_time
            time_text = f'⏱ Total time: {elapsed:.1f}s'

            if self.ai_thread and hasattr(self.ai_thread, '_timing_stats'):
                stats = self.ai_thread._timing_stats
                first_token_max = stats.get('llm_first_token_max', 0)
                output_tokens = stats.get('output_tokens', 0)

                first_token_slow = first_token_max > 10

                if first_token_slow:
                    first_token_html = f'<span style="color: #CC0000;">最慢首token {first_token_max:.1f}s [慢]</span>'
                else:
                    first_token_html = f'最慢首token {first_token_max:.1f}s'

                tpm_html = ''

                if output_tokens > 0:
                    generation_time = stats.get('llm_generation_total', 0)
                    tpm = (generation_time / output_tokens) * 1000 if generation_time > 0 else 0

                    if tpm > 100:
                        tpm_html = f'<span style="color: #CC0000;">平均生成 {tpm:.0f}ms/token [慢]</span>'
                    else:
                        tpm_html = f'平均生成 {tpm:.0f}ms/token'

                if tpm_html:
                    time_text += f'（{first_token_html}，{tpm_html}）'
                else:
                    time_text += f'（{first_token_html}）'

            cursor = self.ai_tab_chat_text.textCursor()
            cursor.movePosition(cursor.End)
            cursor.insertBlock(QTextBlockFormat())
            cursor.insertHtml(f'<span style="color: #888888; font-size: 11px;">{time_text}</span>')
            self.ai_tab_chat_text.setTextCursor(cursor)

        # Add a blank separator line.
        cursor = self.ai_tab_chat_text.textCursor()
        cursor.movePosition(cursor.End)
        cursor.insertBlock(QTextBlockFormat())
        self.ai_tab_chat_text.setTextCursor(cursor)
        self.ai_tab_chat_text.ensureCursorVisible()

        # Extract the full AI answer.
        full_answer = ''

        for msg in reversed(self.ai_messages):
            if msg.get('role') == 'assistant' and msg.get('content'):
                full_answer = msg['content']
                break

        # Save complete conversation to AI log database.
        if hasattr(self, 'ai_log_db_file') and self.ai_log_db_file and hasattr(self, '_current_ai_session_id'):
            try:
                resolution = common_ai_log.auto_judge_resolution(
                    self._current_ai_question,
                    full_answer,
                    self._current_ai_tool_calls,
                )

                common_ai_log.save_conversation(
                    db_file=self.ai_log_db_file,
                    session_id=self._current_ai_session_id,
                    user=CURRENT_USER,
                    cluster='',
                    host=socket.gethostname(),
                    question=self._current_ai_question,
                    answer=full_answer,
                    tool_calls=self._current_ai_tool_calls,
                    resolution=resolution,
                )

                if resolution == 'solved':
                    self._ai_generate_insight(self._current_ai_session_id, self._current_ai_question, full_answer, self._current_ai_tool_calls)
            except Exception as e:
                common.bprint(f'Failed to save AI conversation log: {e}', level='Warning')

        # Show feedback bar.
        self.ai_feedback_widget.show()

    def _ai_tab_user_feedback(self, resolution):
        """User clicked Solved/Unsolved button to override auto-judgment."""
        self.ai_feedback_widget.hide()

        if hasattr(self, 'ai_log_db_file') and self.ai_log_db_file and hasattr(self, '_current_ai_session_id'):
            try:
                common_ai_log.update_resolution(self.ai_log_db_file, self._current_ai_session_id, resolution, user=CURRENT_USER)

                if resolution == 'solved' and hasattr(self, '_current_ai_question'):
                    full_answer = ''

                    for msg in reversed(self.ai_messages):
                        if msg.get('role') == 'assistant' and msg.get('content'):
                            full_answer = msg['content']
                            break

                    if full_answer:
                        self._ai_generate_insight(self._current_ai_session_id, self._current_ai_question, full_answer, self._current_ai_tool_calls)
            except Exception as e:
                common.bprint(f'Failed to update AI resolution: {e}', level='Warning')

    def _ai_generate_insight(self, session_id, question, answer, tool_calls):
        """Launch background thread to generate and save a distilled insight."""
        tool_calls_json = json.dumps(tool_calls or [], ensure_ascii=False)

        self._insight_thread = common_ai_log.InsightGeneratorThread(
            api_base_url=config.ai_api_base_url,
            api_key=config.ai_api_key,
            model_name=config.ai_model_name,
            session_id=session_id,
            question=question,
            answer=answer,
            tool_calls_json=tool_calls_json,
        )
        self._insight_thread.finished_signal.connect(self._ai_on_insight_generated)
        self._insight_thread.start()

    def _ai_on_insight_generated(self, session_id, insight, keywords):
        """Callback when background insight generation completes."""
        if hasattr(self, 'ai_log_db_file') and self.ai_log_db_file:
            try:
                common_ai_log.save_insight(
                    db_file=self.ai_log_db_file,
                    session_id=session_id,
                    insight=insight,
                    keywords=keywords,
                    source_question=self._current_ai_question[:200] if hasattr(self, '_current_ai_question') else '',
                )

                if self.ai_debug_action.isChecked():
                    common.bprint(f'[AI Debug] Insight saved: {insight[:80]}', date_format='%Y-%m-%d %H:%M:%S')
            except Exception as e:
                common.bprint(f'Failed to save AI insight: {e}', level='Warning')

    def ai_tab_on_error(self, error_msg):
        """Show error in chat."""
        self._ai_tab_remove_thinking()
        cursor = self.ai_tab_chat_text.textCursor()
        cursor.movePosition(cursor.End)

        block_fmt = QTextBlockFormat()
        block_fmt.setBackground(QColor('#4A1C24'))
        block_fmt.setLeftMargin(4)
        block_fmt.setRightMargin(4)
        block_fmt.setTopMargin(4)
        block_fmt.setBottomMargin(4)
        cursor.insertBlock(block_fmt)

        char_fmt = QTextCharFormat()
        char_fmt.setForeground(QColor('#F1948A'))
        char_fmt.setFontWeight(QFont.Bold)
        cursor.insertText('Error: ', char_fmt)

        char_fmt.setFontWeight(QFont.Normal)
        cursor.insertText(error_msg, char_fmt)

        self.ai_tab_chat_text.setTextCursor(cursor)

    def ai_tab_clear_chat(self):
        """Clear chat history."""
        self.ai_tab_chat_text.clear()
        self._create_chat_avatars()
        system_prompt = common_ai.SYSTEM_PROMPT.format(db_path=config.db_path, host_list=config.host_list)
        self.ai_messages = [{"role": "system", "content": system_prompt + f"\n\nCurrent user: {CURRENT_USER}"}]
        self.ai_feedback_widget.hide()

    def ai_handle_confirm_request(self, command):
        """Show QMessageBox to confirm dangerous command execution."""
        result = QMessageBox.question(
            self,
            'Confirm Command',
            f'AI wants to execute:\n\n{command}\n\nAllow?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        self.ai_thread.set_confirm_result(result == QMessageBox.Yes)
# For AI TAB (end) #

# For AI Menu (start) #
    def cluster_analysis(self):
        """Cross-reference NETWORK/HOST/STAT/ASSET data, perform SSH tests, and report anomalies."""
        host_ip_set = set(self.host_list_class.host_ip_dic.keys())

        if not host_ip_set:
            QMessageBox.warning(self, 'Warning', 'No hosts configured in host.list.')
            return

        # --- Category 1: Asset consistency data ---

        # Collect network-scanned IPs.
        network_ip_set = set()
        network_ip_info = {}

        for zone in self.network_scan_dic:
            for network in self.network_scan_dic[zone]:
                for ip, info in self.network_scan_dic[zone][network].items():
                    network_ip_set.add(ip)
                    network_ip_info[ip] = {
                        'zone': zone,
                        'network': network,
                        'packet_loss': info.get('packet_loss', ''),
                    }

        # Load Asset data.
        asset_ip_set = set()
        host_asset_file = str(config.db_path) + '/host_asset/host_asset.json'

        if os.path.exists(host_asset_file):
            asset_ip_set = set(self.host_asset_dic.keys())

        # 1a: In HOST but not in NETWORK.
        host_not_in_network = sorted(host_ip_set - network_ip_set)

        # 1b: In NETWORK but not in HOST.
        network_not_in_host = sorted(network_ip_set - host_ip_set)

        # 1c/1d: Asset cross-reference.
        host_not_in_asset = []
        asset_not_in_host_in_network = []
        asset_not_in_host_not_in_network = []

        if asset_ip_set:
            host_not_in_asset = sorted(host_ip_set - asset_ip_set)

            for ip in sorted(asset_ip_set - host_ip_set):
                if ip in network_ip_set:
                    asset_not_in_host_in_network.append(ip)
                else:
                    asset_not_in_host_not_in_network.append(ip)

        # --- Category 2: SSH accessibility test (async with progress) ---

        reply = QMessageBox.question(
            self, 'SSH 连通性测试',
            f'即将对 {len(host_ip_set)} 台主机执行SSH连通性测试（echo命令，timeout=10s）。\n'
            f'并行执行，预计耗时10-30秒。\n\n是否继续？',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

        # Store intermediate data for use in the finished callback.
        self._ca_data = {
            'host_ip_set': host_ip_set,
            'network_ip_set': network_ip_set,
            'network_ip_info': network_ip_info,
            'asset_ip_set': asset_ip_set,
            'host_not_in_network': host_not_in_network,
            'network_not_in_host': network_not_in_host,
            'host_not_in_asset': host_not_in_asset,
            'asset_not_in_host_in_network': asset_not_in_host_in_network,
            'asset_not_in_host_not_in_network': asset_not_in_host_not_in_network,
            'host_asset_file': host_asset_file,
        }

        if reply != QMessageBox.Yes:
            self._cluster_analysis_finish({'ssh_failed': None, 'boot_time': {}})
            return

        total = len(host_ip_set)
        tmp_dir = str(config.db_path) + '/ai_report/.tmp_ssh_test_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs(tmp_dir, exist_ok=True)

        self._ca_progress = QProgressDialog(f'正在测试 0/{total} 台主机...', '取消', 0, total, self)
        self._ca_progress.setWindowTitle('SSH 连通性测试')
        self._ca_progress.setWindowModality(Qt.WindowModal)
        self._ca_progress.setMinimumWidth(450)
        self._ca_progress.setAutoClose(False)
        self._ca_progress.setAutoReset(False)
        self._ca_progress.setValue(0)
        self._ca_progress.show()
        QApplication.processEvents()

        self._ca_ssh_thread = SshTestThread(host_ip_set, tmp_dir)
        self._ca_ssh_thread.progress_signal.connect(self._ssh_test_progress)
        self._ca_ssh_thread.finished_signal.connect(self._cluster_analysis_finish)
        self._ca_progress.canceled.connect(self._ssh_test_cancel)
        self._ca_ssh_thread.start()

    def _ssh_test_progress(self, completed, total, current_ip):
        if hasattr(self, '_ca_progress') and self._ca_progress:
            self._ca_progress.setValue(completed)
            self._ca_progress.setLabelText(
                f'正在测试 {completed}/{total} 台主机...\n当前: {current_ip}'
            )

    def _ssh_test_cancel(self):
        if hasattr(self, '_ca_ssh_thread') and self._ca_ssh_thread:
            self._ca_ssh_thread.stop()

    def _cluster_analysis_finish(self, ssh_results):
        """Callback after SSH test completes (or is skipped). Generates the full report."""
        if hasattr(self, '_ca_progress') and self._ca_progress:
            self._ca_progress.setLabelText('正在生成分析报告...')
            self._ca_progress.setCancelButtonText('')
            self._ca_progress.setMaximum(0)
            QApplication.processEvents()

        ssh_failed_hosts = ssh_results.get('ssh_failed', [])
        boot_time_dic = ssh_results.get('boot_time', {})

        data = self._ca_data
        host_ip_set = data['host_ip_set']
        network_ip_set = data['network_ip_set']
        network_ip_info = data['network_ip_info']
        asset_ip_set = data['asset_ip_set']
        host_not_in_network = data['host_not_in_network']
        network_not_in_host = data['network_not_in_host']
        host_not_in_asset = data['host_not_in_asset']
        asset_not_in_host_in_network = data['asset_not_in_host_in_network']
        asset_not_in_host_not_in_network = data['asset_not_in_host_not_in_network']
        host_asset_file = data['host_asset_file']

        # --- Category 3: Machine anomalies ---

        stat_dic = {}
        stat_timestamp = ''
        host_stat_file = self._find_latest_host_stat_file()

        if host_stat_file and os.path.exists(host_stat_file):
            stat_dic = self.get_stat_info(host_stat_file)
            stat_mtime = os.path.getmtime(host_stat_file)
            stat_timestamp = datetime.datetime.fromtimestamp(stat_mtime).strftime('%Y-%m-%d %H:%M:%S')

        stat_ip_set = set(stat_dic.keys())

        high_load_hosts = []

        for ip, stat in stat_dic.items():
            cpu_thread = stat.get('cpu_thread', 1) or 1
            r15m = stat.get('r15m', 0) or 0

            if r15m > cpu_thread:
                high_load_hosts.append((ip, stat))

        high_load_hosts.sort(key=lambda x: (x[1].get('r15m', 0) or 0) / (x[1].get('cpu_thread', 1) or 1), reverse=True)

        recently_rebooted = []
        long_uptime = []
        io_bottleneck = []
        mem_critical = []
        swap_pressure = []
        disk_low = []

        # Detect "recently rebooted" hosts.
        # Priority: use real-time boot_time from SSH test; fallback to STAT up_days.
        now = datetime.datetime.now()
        rebooted_ips = set()

        for ip, boot_time_str in boot_time_dic.items():
            try:
                boot_time = datetime.datetime.strptime(boot_time_str, '%Y-%m-%d %H:%M:%S')
                up_days = (now - boot_time).days

                if up_days == 0:
                    entry = stat_dic.get(ip, {}).copy()
                    entry['boot_time'] = boot_time_str
                    entry['up_days'] = 0
                    recently_rebooted.append((ip, entry))
                    rebooted_ips.add(ip)
            except ValueError:
                pass

        for ip, stat in stat_dic.items():
            # "Recently rebooted" — skip if already handled via boot_time_dic above.
            if ip not in rebooted_ips and ip not in boot_time_dic:
                if stat.get('up_days', -1) == 0:
                    recently_rebooted.append((ip, stat))

            # "Long uptime" — use boot_time if available, otherwise STAT up_days.
            if ip in boot_time_dic:
                try:
                    boot_dt = datetime.datetime.strptime(boot_time_dic[ip], '%Y-%m-%d %H:%M:%S')
                    ip_up_days = (now - boot_dt).days

                    if ip_up_days > 365:
                        stat_copy = stat.copy()
                        stat_copy['up_days'] = ip_up_days
                        long_uptime.append((ip, stat_copy))
                except ValueError:
                    pass
            else:
                up_days = stat.get('up_days', -1)

                if isinstance(up_days, int) and up_days > 365:
                    long_uptime.append((ip, stat))

            if (stat.get('cpu_wa', 0) or 0) >= 50:
                io_bottleneck.append((ip, stat))

            mem_total = stat.get('mem_total', 0) or 0
            mem_avail = stat.get('mem_avail', 0) or 0

            if mem_total > 0 and mem_avail <= mem_total * 0.1:
                mem_critical.append((ip, stat))

            swap_total = stat.get('swap_total', 0) or 0
            swap_used = stat.get('swap_used', 0) or 0
            swap_free = stat.get('swap_free', 0) or 0

            if swap_total > 0 and swap_used >= swap_total * 0.5:
                swap_pressure.append((ip, stat))
            elif swap_used > 0 and swap_free == 0:
                swap_pressure.append((ip, stat))

            tmp_total = stat.get('tmp_total', 0) or 0
            tmp_avail = stat.get('tmp_avail', 0) or 0

            if tmp_total > 0 and tmp_avail <= tmp_total * 0.1:
                disk_low.append((ip, stat))

        # --- Freshness checks ---
        freshness_info = []
        now = time.time()
        network_scan_file = str(config.db_path) + '/network_scan/network_scan.json'

        for label, filepath, threshold_hours in [
            ('Network Scan', network_scan_file, None),
            ('Host Stat', host_stat_file, 1),
            ('Host Asset', host_asset_file, None),
        ]:
            if os.path.exists(filepath):
                mtime = os.path.getmtime(filepath)
                age_hours = (now - mtime) / 3600

                if threshold_hours is None:
                    status = 'OK'
                else:
                    status = 'WARNING' if age_hours > threshold_hours else 'OK'

                freshness_info.append((label, filepath, mtime, age_hours, status))
            else:
                freshness_info.append((label, filepath, None, None, 'MISSING'))

        # --- Build HTML report ---
        html = self._build_cluster_analysis_html(
            freshness_info=freshness_info,
            host_ip_set=host_ip_set,
            network_ip_set=network_ip_set,
            network_ip_info=network_ip_info,
            asset_ip_set=asset_ip_set,
            host_not_in_network=host_not_in_network,
            network_not_in_host=network_not_in_host,
            host_not_in_asset=host_not_in_asset,
            asset_not_in_host_in_network=asset_not_in_host_in_network,
            asset_not_in_host_not_in_network=asset_not_in_host_not_in_network,
            ssh_failed_hosts=ssh_failed_hosts,
            stat_dic=stat_dic,
            stat_ip_set=stat_ip_set,
            stat_timestamp=stat_timestamp,
            high_load_hosts=high_load_hosts,
            recently_rebooted=recently_rebooted,
            long_uptime=long_uptime,
            io_bottleneck=io_bottleneck,
            mem_critical=mem_critical,
            swap_pressure=swap_pressure,
            disk_low=disk_low,
        )

        if hasattr(self, '_ca_progress') and self._ca_progress:
            self._ca_progress.close()

        # Save to file and open in browser.
        report_dir = str(config.db_path) + '/ai_report'

        try:
            os.makedirs(report_dir, exist_ok=True)
        except PermissionError:
            report_dir = '/tmp/batchRun/ai_report'
            os.makedirs(report_dir, exist_ok=True)

        output_file = report_dir + '/cluster_analysis_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.html'

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        QMessageBox.information(self, 'Cluster Analysis', f'分析完成，点击确定后在浏览器中打开报告。\n\n报告路径：\n{output_file}')
        webbrowser.open('file://' + output_file)

    @staticmethod
    def _classify_ssh_failure(content):
        """Classify SSH failure reason from command output."""
        if 'Timeout exceeded' in content or 'pexpect.exceptions.TIMEOUT' in content:
            return 'SSH超时（网络不通或防火墙阻止）'
        elif 'Permission denied' in content:
            return '认证失败（未配置免密或密码错误）'
        elif 'Connection refused' in content:
            return '连接被拒（SSH服务未启动）'
        elif 'No route to host' in content:
            return '无法路由（网络不通）'
        elif 'Host key verification failed' in content:
            return '主机密钥验证失败'
        elif 'Network is unreachable' in content:
            return '网络不可达'
        else:
            return content[:100] if content else '无输出'

    def _build_cluster_analysis_html(self, **kwargs):
        """Build HTML report for cluster analysis."""
        freshness_info = kwargs['freshness_info']
        host_ip_set = kwargs['host_ip_set']
        network_ip_set = kwargs['network_ip_set']
        network_ip_info = kwargs['network_ip_info']
        asset_ip_set = kwargs['asset_ip_set']
        host_not_in_network = kwargs['host_not_in_network']
        network_not_in_host = kwargs['network_not_in_host']
        host_not_in_asset = kwargs['host_not_in_asset']
        asset_not_in_host_in_network = kwargs['asset_not_in_host_in_network']
        asset_not_in_host_not_in_network = kwargs['asset_not_in_host_not_in_network']
        ssh_failed_hosts = kwargs['ssh_failed_hosts']
        stat_dic = kwargs['stat_dic']
        stat_ip_set = kwargs['stat_ip_set']
        stat_timestamp = kwargs['stat_timestamp']
        high_load_hosts = kwargs['high_load_hosts']
        recently_rebooted = kwargs['recently_rebooted']
        long_uptime = kwargs['long_uptime']
        io_bottleneck = kwargs['io_bottleneck']
        mem_critical = kwargs['mem_critical']
        swap_pressure = kwargs['swap_pressure']
        disk_low = kwargs['disk_low']

        css = """
* { box-sizing: border-box; }
body { background: #19232D; color: #D5D8DC; font-family: -apple-system, "Microsoft YaHei", sans-serif;
       font-size: 14px; margin: 0; padding: 0; display: flex; }
nav { position: fixed; top: 0; left: 0; width: 220px; height: 100vh; background: #151D26;
      border-right: 1px solid #2C3E50; padding: 20px 12px; overflow-y: auto; z-index: 100; }
nav h3 { color: #5DADE2; font-size: 14px; margin: 0 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid #2C3E50; }
nav a { display: block; color: #AEB6BF; text-decoration: none; padding: 6px 10px; margin: 2px 0;
        border-radius: 4px; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
nav a:hover { background: #1E2A35; color: #5DADE2; }
nav a.nav-sub { padding-left: 22px; font-size: 12px; color: #7F8C8D; }
main { margin-left: 220px; padding: 25px 35px; flex: 1; min-width: 0; padding-top: 60px; }
h2 { color: #5DADE2; border-bottom: 2px solid #2C3E50; padding-bottom: 8px;
     position: fixed; top: 0; left: 220px; right: 0; margin: 0; padding: 12px 35px;
     background: #19232D; z-index: 100; }
h3 { color: #48C9B0; margin-top: 28px; }
h4 { color: #ABB2B9; margin-top: 15px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { border: 1px solid #4A4A4A; padding: 5px 10px; text-align: left; font-size: 13px; }
th { background: #2C3E50; color: #AED6F1; white-space: nowrap; }
tr:nth-child(even) { background: #1E2A35; }
.ok { color: #2ECC71; } .warn { color: #E74C3C; font-weight: bold; }
.missing { color: #95A5A6; font-style: italic; }
.risk-box { background: #2C1010; border: 2px solid #E74C3C; border-radius: 8px; padding: 15px 20px; margin: 15px 0; }
.risk-box h3 { color: #E74C3C; margin-top: 0; }
.warn-box { background: #2C2410; border: 2px solid #F39C12; border-radius: 8px; padding: 15px 20px; margin: 15px 0; }
.warn-box h3 { color: #F39C12; margin-top: 0; }
.risk-item { margin: 6px 0; padding: 4px 0; }
.conclusion-box { background: #1E2A35; border: 1px solid #34495E; border-radius: 8px; padding: 12px 18px; margin: 10px 0; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 6px; }
.badge-danger { background: #641E16; color: #F1948A; }
.badge-warning { background: #7D6608; color: #F9E79F; }
.badge-ok { background: #1E4620; color: #82E0AA; }
.badge-security { background: #4A1A6B; color: #D2B4DE; }
.badge-config { background: #0E4B5A; color: #76D7C4; }
.badge-resource { background: #4A3000; color: #F0B27A; }
.stat-time { color: #95A5A6; font-size: 12px; margin-left: 10px; }
.collapse-wrap { position: relative; }
.row-toggle { display: none; }
.collapse-wrap tr.extra { display: none; }
.row-toggle:checked ~ table tr.extra { display: table-row; }
tfoot td { padding: 0; border-top: 1px solid #4A4A4A; border-bottom: none; }
.more-toggle { display: block; cursor: pointer; user-select: none; text-align: center;
               font-size: 13px; color: #5DADE2; font-weight: 600; padding: 9px 12px; background: #2C3E50; }
.more-toggle:hover { background: #34495E; }
.more-toggle .ico { color: #95A5A6; margin-right: 4px; }
.more-toggle .hide { display: none; }
.row-toggle:checked ~ table .more-toggle .show { display: none; }
.row-toggle:checked ~ table .more-toggle .hide { display: inline; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { background: #34495E; }
th.sortable::after { content: ' \\2195'; color: #7F8C8D; font-size: 11px; }
"""

        sort_js = """
<script>
document.addEventListener('click', function(e) {
    var th = e.target.closest('th.sortable');
    if (!th) return;
    var table = th.closest('table');
    var tbody = table.querySelector('tbody') || table;
    var idx = Array.from(th.parentNode.children).indexOf(th);
    var rows = Array.from(tbody.querySelectorAll('tr:not(.extra-hidden)'));
    if (rows.length === 0) rows = Array.from(tbody.querySelectorAll('tr')).filter(function(r){return !r.querySelector('th');});
    var asc = th.getAttribute('data-sort-dir') !== 'asc';
    th.setAttribute('data-sort-dir', asc ? 'asc' : 'desc');
    Array.from(th.parentNode.children).forEach(function(s){if(s!==th)s.removeAttribute('data-sort-dir');});
    rows.sort(function(a, b) {
        var ac = (a.children[idx]||{}).textContent||'';
        var bc = (b.children[idx]||{}).textContent||'';
        var an = parseFloat(ac.replace(/[^\\d.\\-]/g,''));
        var bn = parseFloat(bc.replace(/[^\\d.\\-]/g,''));
        if (!isNaN(an) && !isNaN(bn)) return asc ? an-bn : bn-an;
        return asc ? ac.localeCompare(bc) : bc.localeCompare(ac);
    });
    var limit = parseInt(table.getAttribute('data-collapse')||'0',10);
    rows.forEach(function(r,i){
        tbody.appendChild(r);
        if(limit>0){if(i<limit)r.classList.remove('extra');else r.classList.add('extra');}
    });
});
</script>
"""

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [f'<html><head><meta charset="utf-8"><style>{css}</style></head><body>{sort_js}']

        # --- Left navigation ---
        lines.append('<nav>')
        lines.append('<h3>目录导航</h3>')
        lines.append('<a href="#sec-freshness">数据新鲜度</a>')
        lines.append('<a href="#sec-cat1">1. 不可访问设备</a>')
        lines.append('<a href="#sec-cat2">2. 资产一致性</a>')
        lines.append('<a href="#sec-2a" class="nav-sub">2a. 未覆盖网络扫描</a>')
        lines.append('<a href="#sec-2b" class="nav-sub">2b. 网络中未登记主机</a>')

        if asset_ip_set:
            lines.append('<a href="#sec-2c" class="nav-sub">2c. Asset未登记</a>')
            lines.append('<a href="#sec-2d" class="nav-sub">2d. Host未登记</a>')

        lines.append('<a href="#sec-cat3">3. 机器异常</a>')
        lines.append('<a href="#sec-3a" class="nav-sub">3a. 高负载</a>')
        lines.append('<a href="#sec-3b" class="nav-sub">3b. 近期重启</a>')
        lines.append('<a href="#sec-3c" class="nav-sub">3c. 长期未重启</a>')
        lines.append('<a href="#sec-3d" class="nav-sub">3d. I/O 瓶颈</a>')
        lines.append('<a href="#sec-3e" class="nav-sub">3e. 内存告急</a>')
        lines.append('<a href="#sec-3f" class="nav-sub">3f. Swap 压力</a>')
        lines.append('<a href="#sec-3g" class="nav-sub">3g. 磁盘不足</a>')
        lines.append('<a href="#sec-summary">分析汇总</a>')
        lines.append('</nav>')

        # --- Main content ---
        lines.append('<main>')
        lines.append('<h2>集群分析报告</h2>')
        lines.append(f'<p><i>生成时间：{timestamp}</i></p>')

        # --- Data freshness ---
        lines.append('<h3 id="sec-freshness">数据新鲜度</h3>')
        lines.append('<table><tr><th>数据源</th><th>文件路径</th><th>数据年龄</th><th>状态</th></tr>')

        for label, filepath, mtime, age_hours, status in freshness_info:
            if status == 'MISSING':
                lines.append(f'<tr><td>{label}</td><td>{filepath}</td><td class="missing">N/A</td><td class="warn">缺失</td></tr>')
            else:
                if age_hours >= 24:
                    age_str = f'{age_hours / 24:.1f} 天'
                else:
                    age_str = f'{age_hours:.1f} 小时'

                status_class = 'ok' if status == 'OK' else 'warn'
                status_text = '正常' if status == 'OK' else '过期'
                lines.append(f'<tr><td>{label}</td><td>{filepath}</td><td>{age_str}</td><td class="{status_class}">{status_text}</td></tr>')

        lines.append('</table>')

        # --- Section helper for collapsible tables ---
        collapse_id = [0]

        def collapsible_table(headers, rows, col_count):
            """Generate table HTML with folding if rows > 10 and sortable headers."""
            limit = 10
            th_row = '<tr>' + ''.join(f'<th class="sortable">{h}</th>' for h in headers) + '</tr>'

            if len(rows) <= limit:
                html_parts = [f'<table><thead>{th_row}</thead><tbody>']
                html_parts.extend(rows)
                html_parts.append('</tbody></table>')
                return '\n'.join(html_parts)

            collapse_id[0] += 1
            cid = f'tbl-{collapse_id[0]}'
            visible_rows = rows[:limit]
            hidden_rows = [r.replace('<tr>', '<tr class="extra">', 1) for r in rows[limit:]]

            html_parts = ['<div class="collapse-wrap">']
            html_parts.append(f'<input type="checkbox" id="{cid}" class="row-toggle">')
            html_parts.append(f'<table data-collapse="{limit}"><thead>{th_row}</thead><tbody>')
            html_parts.extend(visible_rows)
            html_parts.extend(hidden_rows)
            html_parts.append('</tbody>')
            html_parts.append(f'<tfoot><tr><td colspan="{col_count}">'
                              f'<label class="more-toggle" for="{cid}">'
                              f'<span class="ico">&#9656;</span>'
                              f'<span class="show">展开其余 {len(hidden_rows)} 行</span>'
                              f'<span class="ico hide">&#9662;</span>'
                              f'<span class="hide">收起</span>'
                              f'</label></td></tr></tfoot>')
            html_parts.append('</table>')
            html_parts.append('</div>')
            return '\n'.join(html_parts)

        def get_subnet(ip):
            """Derive /24 subnet from IP address."""
            parts = ip.rsplit('.', 1)
            return parts[0] + '.0/24' if len(parts) == 2 else ip

        def get_host_extra_info(ip):
            """Get server_type and OS from host_info_dic."""
            info = self.host_info_dic.get(ip, {})
            return info.get('server_type', ''), info.get('os', '')

        # ===== Category 1: 不可访问设备 =====
        lines.append('<h3 id="sec-cat1">1. 不可访问设备（SSH连通性测试）</h3>')

        if ssh_failed_hosts:
            lines.append(f'<div class="conclusion-box"><b>结论：</b>对 {len(host_ip_set)} 台主机执行SSH测试，'
                         f'其中 <b>{len(ssh_failed_hosts)}</b> 台无法访问。</div>')
            rows = []

            for ip, reason in ssh_failed_hosts:
                info = self.host_list_class.host_ip_dic.get(ip, {})
                hostname = '  '.join(info.get('host_name', []))
                groups = '  '.join(info.get('groups', []))
                server_type, os_info = get_host_extra_info(ip)
                rows.append(f'<tr><td>{ip}</td><td>{hostname}</td><td>{server_type}</td><td>{groups}</td>'
                            f'<td>{os_info}</td><td class="warn">{reason}</td></tr>')

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '操作系统', '失败原因'], rows, 6))
        elif ssh_failed_hosts is not None:
            lines.append(f'<p class="ok">所有 {len(host_ip_set)} 台主机SSH连通性测试通过。</p>')
        else:
            lines.append('<p class="missing">未执行SSH连通性测试。</p>')

        # ===== Category 2: 资产一致性 =====
        lines.append('<h3 id="sec-cat2">2. 资产一致性（NETWORK / ASSET / HOST 三方对比）</h3>')

        # --- 2a: HOST not in NETWORK ---
        lines.append('<h4 id="sec-2a">2a. 未覆盖网络扫描的主机（在HOST中，不在NETWORK中）</h4>')

        if not network_ip_set:
            lines.append('<p class="missing">无网络扫描数据，跳过此项检查。</p>')
        elif host_not_in_network:
            subnet_counts = {}

            for ip in host_not_in_network:
                subnet = get_subnet(ip)

                if subnet not in subnet_counts:
                    subnet_counts[subnet] = 0

                subnet_counts[subnet] += 1

            subnet_summary = '、'.join(f'{s}({c}台)' for s, c in sorted(subnet_counts.items(), key=lambda x: -x[1])[:10])
            lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(host_not_in_network)} 台已登记主机不在网络扫描范围内。'
                         f'涉及网段：{subnet_summary}。'
                         f'<br>可能原因：网络扫描配置未覆盖对应网段，或host.list中存在已下线但未清理的条目。</div>')
            rows = []

            for ip in host_not_in_network:
                info = self.host_list_class.host_ip_dic.get(ip, {})
                hostname = '  '.join(info.get('host_name', []))
                groups = '  '.join(info.get('groups', []))
                server_type, os_info = get_host_extra_info(ip)
                subnet = get_subnet(ip)
                rows.append(f'<tr><td>{ip}</td><td>{subnet}</td><td>{hostname}</td><td>{server_type}</td><td>{groups}</td><td>{os_info}</td></tr>')

            lines.append(collapsible_table(['IP', '所属网段', '主机名', '服务器类型', '分组', '操作系统'], rows, 6))
        else:
            lines.append('<p class="ok">所有已登记主机均在网络扫描覆盖范围内。</p>')

        # --- 2b: NETWORK not in HOST ---
        lines.append('<h4 id="sec-2b">2b. 网络中未登记主机（在NETWORK中，不在HOST中）</h4>')

        if not network_ip_set:
            lines.append('<p class="missing">无网络扫描数据，跳过此项检查。</p>')
        elif network_not_in_host:
            lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(network_not_in_host)} 个IP在网络扫描中发现但未在host.list中登记。'
                         f'可能原因：新上架机器尚未录入，或属于非管辖设备。</div>')
            rows = []

            for ip in network_not_in_host:
                info = network_ip_info.get(ip, {})
                rows.append(f'<tr><td>{ip}</td><td>{info.get("zone", "")}</td><td>{info.get("network", "")}</td>'
                            f'<td>{info.get("packet_loss", "")}</td></tr>')

            lines.append(collapsible_table(['IP', '区域', '网段', '丢包率'], rows, 4))
        else:
            lines.append('<p class="ok">网络扫描中未发现未登记主机。</p>')

        # --- 2c: HOST not in ASSET ---
        if asset_ip_set:
            lines.append('<h4 id="sec-2c">2c. HOST中有但ASSET中未登记（资产台账不全）</h4>')

            if host_not_in_asset:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(host_not_in_asset)} 台主机已在HOST中登记但未出现在ASSET资产台账中。'
                             f'说明资产登记不全，需要补录。</div>')
                rows = []

                for ip in host_not_in_asset:
                    info = self.host_list_class.host_ip_dic.get(ip, {})
                    hostname = '  '.join(info.get('host_name', []))
                    groups = '  '.join(info.get('groups', []))
                    server_type, os_info = get_host_extra_info(ip)
                    in_network = '是' if ip in network_ip_set else '否'
                    rows.append(f'<tr><td>{ip}</td><td>{hostname}</td><td>{server_type}</td><td>{groups}</td><td>{os_info}</td><td>{in_network}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '操作系统', '在NETWORK中'], rows, 6))
            else:
                lines.append('<p class="ok">所有HOST中的主机均已在ASSET中登记。</p>')

            # --- 2d: ASSET not in HOST ---
            lines.append('<h4 id="sec-2d">2d. ASSET中有但HOST中未登记</h4>')

            if asset_not_in_host_in_network or asset_not_in_host_not_in_network:
                total_asset_only = len(asset_not_in_host_in_network) + len(asset_not_in_host_not_in_network)
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{total_asset_only} 台资产未在HOST中登记。'
                             f'其中 {len(asset_not_in_host_in_network)} 台在网络扫描中可见（HOST漏登记），'
                             f'{len(asset_not_in_host_not_in_network)} 台不在网络扫描范围内（可能属于其他网段或已下线）。</div>')

                all_asset_only_ips = asset_not_in_host_in_network + asset_not_in_host_not_in_network
                asset_fields = []

                for ip in all_asset_only_ips:
                    for key in self.host_asset_dic.get(ip, {}).keys():
                        if key not in asset_fields:
                            asset_fields.append(key)

                if asset_not_in_host_in_network:
                    lines.append('<p><b>在NETWORK中可见（HOST漏登记，需补录host.list）：</b></p>')
                    headers = ['IP', '区域', '网段'] + asset_fields
                    rows = []

                    for ip in asset_not_in_host_in_network:
                        net_info = network_ip_info.get(ip, {})
                        asset_info = self.host_asset_dic.get(ip, {})
                        asset_cells = ''.join(f'<td>{asset_info.get(f, "")}</td>' for f in asset_fields)
                        rows.append(f'<tr><td>{ip}</td><td>{net_info.get("zone", "")}</td><td>{net_info.get("network", "")}</td>{asset_cells}</tr>')

                    lines.append(collapsible_table(headers, rows, len(headers)))

                if asset_not_in_host_not_in_network:
                    lines.append('<p><b>不在NETWORK中（其他网段或已下线，需核实资产状态）：</b></p>')
                    headers = ['IP'] + asset_fields
                    rows = []

                    for ip in asset_not_in_host_not_in_network:
                        asset_info = self.host_asset_dic.get(ip, {})
                        asset_cells = ''.join(f'<td>{asset_info.get(f, "")}</td>' for f in asset_fields)
                        rows.append(f'<tr><td>{ip}</td>{asset_cells}</tr>')

                    lines.append(collapsible_table(headers, rows, len(headers)))
            else:
                lines.append('<p class="ok">ASSET中所有资产均已在HOST中登记。</p>')

        # ===== Category 3: 机器异常 =====
        stat_time_note = f'<span class="stat-time">（采样时间：{stat_timestamp}）</span>' if stat_timestamp else ''
        lines.append(f'<h3 id="sec-cat3">3. 机器异常分析{stat_time_note}</h3>')

        if not stat_dic:
            lines.append('<p class="missing">无负载采样数据，跳过此项检查。</p>')
        else:
            # 3a: High load.
            lines.append('<h4 id="sec-3a">3a. 高负载（15分钟平均负载 &gt; CPU线程数）</h4>')

            if high_load_hosts:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(high_load_hosts)} 台主机负载超过CPU核心数，处于过载状态。</div>')
                rows = []

                for ip, stat in high_load_hosts:
                    hostname = stat.get('host_name', '')
                    server_type, _ = get_host_extra_info(ip)
                    groups = stat.get('groups', '')
                    r15m = stat.get('r15m', 0) or 0
                    cpu_thread = stat.get('cpu_thread', 1) or 1
                    ratio = f'{r15m / cpu_thread:.1f}x'
                    mem_avail = stat.get('mem_avail', 0) or 0
                    mem_total = stat.get('mem_total', 0) or 0
                    rows.append(f'<tr><td>{ip}</td><td>{hostname}</td><td>{server_type}</td><td>{groups}</td><td>{r15m}</td><td>{cpu_thread}</td>'
                                f'<td class="warn">{ratio}</td><td>{mem_avail}</td><td>{mem_total}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', 'r15m', 'CPU线程', '负载倍率', '可用内存(GB)', '总内存(GB)'], rows, 9))
            else:
                lines.append('<p class="ok">所有主机负载均在正常范围内。</p>')

            # 3b: Recently rebooted.
            lines.append('<h4 id="sec-3b">3b. 近期重启（up_days = 0）</h4>')

            if recently_rebooted:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(recently_rebooted)} 台主机今日有重启记录，请确认是否为计划内维护。</div>')
                rows = []

                for ip, stat in recently_rebooted:
                    server_type, _ = get_host_extra_info(ip)
                    boot_time = stat.get('boot_time', '')
                    rows.append(f'<tr><td>{ip}</td><td>{stat.get("host_name", "")}</td><td>{server_type}</td><td>{stat.get("groups", "")}</td><td>{boot_time}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '启动时间'], rows, 5))
            else:
                lines.append('<p class="ok">无近期重启主机。</p>')

            # 3c: Long uptime (> 365 days).
            lines.append('<h4 id="sec-3c">3c. 长期未重启（运行超过365天）</h4>')

            if long_uptime:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(long_uptime)} 台主机运行超过365天未重启，可能缺少内核安全补丁。</div>')
                rows = []

                for ip, stat in long_uptime:
                    server_type, _ = get_host_extra_info(ip)
                    rows.append(f'<tr><td>{ip}</td><td>{stat.get("host_name", "")}</td><td>{server_type}</td><td>{stat.get("groups", "")}</td><td class="warn">{stat.get("up_days", "")}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '运行天数'], rows, 5))
            else:
                lines.append('<p class="ok">无长期未重启主机。</p>')

            # 3d: I/O bottleneck.
            lines.append('<h4 id="sec-3d">3d. I/O 瓶颈（cpu_wa &gt; 50%）</h4>')

            if io_bottleneck:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(io_bottleneck)} 台主机I/O等待严重，可能存在磁盘性能瓶颈或NFS挂载异常。</div>')
                rows = []

                for ip, stat in io_bottleneck:
                    server_type, _ = get_host_extra_info(ip)
                    rows.append(f'<tr><td>{ip}</td><td>{stat.get("host_name", "")}</td><td>{server_type}</td><td>{stat.get("groups", "")}</td><td class="warn">{stat.get("cpu_wa", 0)}%</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', 'CPU Wait %'], rows, 5))
            else:
                lines.append('<p class="ok">无I/O瓶颈主机。</p>')

            # 3e: Memory critical.
            lines.append('<h4 id="sec-3e">3e. 内存告急（可用 &lt; 总量10%）</h4>')

            if mem_critical:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(mem_critical)} 台主机可用内存不足10%，存在OOM风险。</div>')
                rows = []

                for ip, stat in mem_critical:
                    server_type, _ = get_host_extra_info(ip)
                    mem_total = stat.get('mem_total', 0) or 0
                    mem_avail = stat.get('mem_avail', 0) or 0
                    usage = f'{((mem_total - mem_avail) / mem_total * 100):.0f}%' if mem_total > 0 else 'N/A'
                    rows.append(f'<tr><td>{ip}</td><td>{stat.get("host_name", "")}</td><td>{server_type}</td><td>{stat.get("groups", "")}</td>'
                                f'<td>{mem_avail}</td><td>{mem_total}</td><td class="warn">{usage}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '可用内存(GB)', '总内存(GB)', '使用率'], rows, 7))
            else:
                lines.append('<p class="ok">无内存告急主机。</p>')

            # 3f: Swap pressure.
            lines.append('<h4 id="sec-3f">3f. Swap 压力（使用 &gt; 总量50%）</h4>')

            if swap_pressure:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(swap_pressure)} 台主机Swap使用过高，实际内存可能不足。</div>')
                rows = []

                for ip, stat in swap_pressure:
                    server_type, _ = get_host_extra_info(ip)
                    swap_total = stat.get('swap_total', 0) or 0
                    swap_used = stat.get('swap_used', 0) or 0
                    swap_avail = round(swap_total - swap_used, 2)
                    avail_cls = ' class="warn"' if (swap_total > 0 and swap_avail < swap_total * 0.1) else ''
                    rows.append(f'<tr><td>{ip}</td><td>{stat.get("host_name", "")}</td><td>{server_type}</td><td>{stat.get("groups", "")}</td>'
                                f'<td>{swap_used}</td><td{avail_cls}>{swap_avail}</td><td>{swap_total}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', 'Swap已用(GB)', 'Swap可用(GB)', 'Swap总量(GB)'], rows, 7))
            else:
                lines.append('<p class="ok">无Swap压力主机。</p>')

            # 3g: Disk low.
            lines.append('<h4 id="sec-3g">3g. 磁盘空间不足（/tmp可用 &lt; 总量10%）</h4>')

            if disk_low:
                lines.append(f'<div class="conclusion-box"><b>结论：</b>{len(disk_low)} 台主机/tmp空间不足10%，可能影响任务运行。</div>')
                rows = []

                for ip, stat in disk_low:
                    server_type, _ = get_host_extra_info(ip)
                    rows.append(f'<tr><td>{ip}</td><td>{stat.get("host_name", "")}</td><td>{server_type}</td><td>{stat.get("groups", "")}</td>'
                                f'<td>{stat.get("tmp_avail", 0)}</td><td>{stat.get("tmp_total", 0)}</td></tr>')

                lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '/tmp可用(GB)', '/tmp总量(GB)'], rows, 6))
            else:
                lines.append('<p class="ok">无磁盘空间不足主机。</p>')

        # ===== Summary =====
        lines.append('<h3 id="sec-summary">分析汇总</h3>')

        high_risks = []
        warnings = []

        for label, filepath, mtime, age_hours, status in freshness_info:
            if status == 'MISSING':
                high_risks.append(f'数据源缺失：<b>{label}</b>（文件不存在）')
            elif status == 'WARNING':
                age_text = f'{age_hours / 24:.1f} 天' if age_hours >= 24 else f'{age_hours:.1f} 小时'
                warnings.append(f'数据过期：<b>{label}</b>（{age_text}未更新）')

        if ssh_failed_hosts and len(ssh_failed_hosts) > len(host_ip_set) * 0.3:
            high_risks.append(f'大量主机不可访问：<b>{len(ssh_failed_hosts)}</b> 台SSH失败（超过30%）')
        elif ssh_failed_hosts:
            warnings.append(f'{len(ssh_failed_hosts)} 台主机SSH不可达')

        if high_load_hosts:
            if len(high_load_hosts) > len(stat_ip_set) * 0.3:
                high_risks.append(f'集群负载严重：<b>{len(high_load_hosts)}</b> 台主机过载（超过30%）')
            else:
                warnings.append(f'{len(high_load_hosts)} 台主机负载过高')

        if mem_critical:
            high_risks.append(f'内存告急：<b>{len(mem_critical)}</b> 台主机可用内存不足10%')

        if io_bottleneck:
            high_risks.append(f'I/O 瓶颈：<b>{len(io_bottleneck)}</b> 台主机 CPU 等待超过50%')

        if disk_low:
            warnings.append(f'{len(disk_low)} 台主机 /tmp 空间不足10%')

        if swap_pressure:
            warnings.append(f'{len(swap_pressure)} 台主机 swap 使用超过50%')

        if long_uptime:
            warnings.append(f'{len(long_uptime)} 台主机运行超过365天未重启')

        if network_not_in_host:
            warnings.append(f'{len(network_not_in_host)} 个网络扫描IP未在host.list中登记')

        if host_not_in_network and network_ip_set:
            warnings.append(f'{len(host_not_in_network)} 台已登记主机不在网络扫描范围内')

        if host_not_in_asset:
            warnings.append(f'{len(host_not_in_asset)} 台主机未在ASSET资产台账中登记')

        if asset_not_in_host_in_network:
            warnings.append(f'{len(asset_not_in_host_in_network)} 台资产在网络中可见但未在HOST中登记')

        # Overall assessment.
        lines.append('<h4>总体评估</h4>')
        lines.append('<div class="conclusion-box">')
        asset_str = f' | 资产台账 (ASSET)：<b>{len(asset_ip_set)}</b> 台' if asset_ip_set else ''
        lines.append(f'<p>已登记主机 (HOST)：<b>{len(host_ip_set)}</b> 台 | '
                     f'网络扫描 (NETWORK)：<b>{len(network_ip_set)}</b> 个IP | '
                     f'负载采样 (STAT)：<b>{len(stat_ip_set)}</b> 台{asset_str}</p>')

        if not high_risks and not warnings:
            lines.append('<p><span class="badge badge-ok">健康</span>集群各项指标正常，未发现需要处理的异常。</p>')
        elif high_risks:
            lines.append(f'<p><span class="badge badge-danger">需立即处理</span>'
                         f'发现 <b>{len(high_risks)}</b> 项高风险问题和 <b>{len(warnings)}</b> 项需关注问题，建议优先处理高风险告警。</p>')
        else:
            lines.append(f'<p><span class="badge badge-warning">需关注</span>'
                         f'发现 <b>{len(warnings)}</b> 项需关注问题，暂无高风险告警。</p>')

        asset_stat_str = f' | Asset未登记：{len(host_not_in_asset)} | Host未登记(Asset)：{len(asset_not_in_host_in_network) + len(asset_not_in_host_not_in_network)}' if asset_ip_set else ''
        lines.append(f'<p>异常统计 — 不可访问：{len(ssh_failed_hosts) if ssh_failed_hosts else "未测试"} | '
                     f'未覆盖扫描：{len(host_not_in_network)} | 未登记：{len(network_not_in_host)} | '
                     f'高负载：{len(high_load_hosts)} | '
                     f'重启：{len(recently_rebooted)} | I/O：{len(io_bottleneck)} | '
                     f'内存：{len(mem_critical)} | Swap：{len(swap_pressure)} | 磁盘：{len(disk_low)}{asset_stat_str}</p>')
        lines.append('</div>')

        if high_risks:
            lines.append('<h4>&#9888; 高风险告警</h4>')
            lines.append('<div class="risk-box">')

            for item in high_risks:
                lines.append(f'<div class="risk-item"><span class="badge badge-danger">严重</span>{item}</div>')

            lines.append('</div>')

        if warnings:
            lines.append('<h4>&#9888; 需要关注</h4>')
            lines.append('<div class="warn-box">')

            for item in warnings:
                lines.append(f'<div class="risk-item"><span class="badge badge-warning">注意</span>{item}</div>')

            lines.append('</div>')

        # Recommended actions.
        lines.append('<h4>建议操作</h4>')
        lines.append('<div class="conclusion-box" style="border-color: #5B7B9D;">')
        actions = []

        if network_not_in_host:
            actions.append(f'<span class="badge badge-security">安全</span>'
                           f'网络中发现 {len(network_not_in_host)} 个未登记IP，需管理员逐一核查：'
                           f'确认是否为未经授权接入的设备（安全风险），或为新上架机器需补录host.list')

        if ssh_failed_hosts:
            actions.append(f'<span class="badge badge-config">配置</span>'
                           f'{len(ssh_failed_hosts)} 台主机SSH不可达，需排查：'
                           f'SSH免密是否配置、SSH服务是否正常、网络是否可达')

        if host_not_in_network and network_ip_set:
            actions.append(f'<span class="badge badge-config">配置</span>'
                           f'{len(host_not_in_network)} 台已登记主机不在网络扫描范围内，需核查：'
                           f'是network_scan配置缺少对应网段，还是机器已下线/迁移但host.list未更新')

        for label, filepath, mtime, age_hours, status in freshness_info:
            if status == 'MISSING':
                actions.append(f'<span class="badge badge-config">配置</span>'
                               f'{label}数据缺失，请执行对应采集任务生成基线数据')
            elif status == 'WARNING':
                age_text = f'{age_hours / 24:.0f}天' if age_hours >= 24 else f'{age_hours:.0f}小时'
                actions.append(f'<span class="badge badge-config">配置</span>'
                               f'{label}数据已过期{age_text}，请重新执行采集任务以获取最新状态')

        if mem_critical:
            actions.append(f'<span class="badge badge-resource">资源</span>'
                           f'{len(mem_critical)} 台主机内存告急，排查异常进程（top/ps），必要时kill或迁移任务以避免OOM')

        if io_bottleneck:
            actions.append(f'<span class="badge badge-resource">资源</span>'
                           f'{len(io_bottleneck)} 台主机I/O瓶颈，检查磁盘健康（smartctl）和NFS挂载状态')

        if high_load_hosts:
            actions.append(f'<span class="badge badge-resource">资源</span>'
                           f'{len(high_load_hosts)} 台主机过载，分析进程列表确认是否有僵尸进程或需扩容/负载均衡')

        if disk_low:
            actions.append(f'<span class="badge badge-resource">资源</span>'
                           f'{len(disk_low)} 台主机/tmp空间不足，清理临时文件和过期日志')

        if swap_pressure:
            actions.append(f'<span class="badge badge-resource">资源</span>'
                           f'{len(swap_pressure)} 台主机Swap压力大，评估是否需要增加物理内存或限制任务并发')

        if host_not_in_asset:
            actions.append(f'<span class="badge badge-config">配置</span>'
                           f'{len(host_not_in_asset)} 台主机未在ASSET资产台账中登记，需联系资产管理员补录')

        if asset_not_in_host_in_network:
            actions.append(f'<span class="badge badge-config">配置</span>'
                           f'{len(asset_not_in_host_in_network)} 台资产在网络中可见但未在HOST中登记，'
                           f'需确认是否应纳入管理并补录host.list')

        if asset_not_in_host_not_in_network:
            actions.append(f'<span class="badge badge-config">配置</span>'
                           f'{len(asset_not_in_host_not_in_network)} 台资产既不在HOST也不在NETWORK中，'
                           f'需核实设备是否已下线/迁移/归还，及时更新ASSET台账')

        if not actions:
            actions.append('<span class="badge badge-ok">无</span>当前无需特别操作，建议保持定期采样监控')

        for i, action in enumerate(actions, 1):
            lines.append(f'<p>{i}. {action}</p>')

        lines.append('</div>')

        lines.append('</main>')
        lines.append('</body></html>')

        return '\n'.join(lines)

    def security_analysis(self):
        """Hybrid security analysis: passive data + active SSH scanning."""
        host_ip_dic = self.host_list_class.host_ip_dic

        if not host_ip_dic:
            QMessageBox.warning(self, 'Warning', '未配置主机列表 (host.list)，无法执行安全分析。')
            return

        host_list = []

        for ip, info in host_ip_dic.items():
            ssh_port = info.get('ssh_port', None)
            host_list.append((ip, ssh_port))

        total = len(host_list)

        reply = QMessageBox.question(
            self, 'Security Analysis',
            f'即将对 {total} 台主机进行安全扫描。\n'
            f'扫描将通过SSH执行只读安全检查命令（约30秒/主机）。\n\n'
            f'是否继续？',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )

        if reply != QMessageBox.Yes:
            return

        self._sec_progress = QProgressDialog('正在收集被动数据...', '取消', 0, total, self)
        self._sec_progress.setWindowTitle('安全扫描进度')
        self._sec_progress.setWindowModality(Qt.WindowModal)
        self._sec_progress.setMinimumWidth(450)
        self._sec_progress.setValue(0)
        self._sec_progress.show()
        QApplication.processEvents()

        passive_data = self._collect_passive_security_data()

        self._sec_progress.setLabelText(f'正在扫描 0/{total} 台主机...')

        self._sec_scan_start_time = time.time()
        self._sec_passive_data = passive_data

        self._sec_scan_thread = SecurityScanThread(
            host_list=host_list,
            user=CURRENT_USER,
            parallel=min(len(host_list), 128),
            timeout=180
        )
        self._sec_scan_thread.progress_signal.connect(self._security_scan_progress)
        self._sec_scan_thread.finished_signal.connect(self._security_scan_finished)
        self._sec_progress.canceled.connect(self._security_scan_cancel)
        self._sec_scan_thread.start()

    def _security_scan_progress(self, completed, total, current_ip):
        if hasattr(self, '_sec_progress') and self._sec_progress:
            self._sec_progress.setValue(completed)
            self._sec_progress.setLabelText(
                f'正在扫描 {completed}/{total} 台主机...\n当前: {current_ip}'
            )

    def _security_scan_cancel(self):
        if hasattr(self, '_sec_scan_thread') and self._sec_scan_thread:
            self._sec_scan_thread.stop()

    def _security_scan_finished(self, raw_results):
        scan_duration = time.time() - self._sec_scan_start_time
        passive_data = self._sec_passive_data

        if hasattr(self, '_sec_progress') and self._sec_progress:
            self._sec_progress.setLabelText('正在生成分析报告...')
            self._sec_progress.setCancelButtonText('')
            self._sec_progress.setMaximum(0)
            QApplication.processEvents()

        findings = self._parse_security_scan_results(raw_results)

        html = self._build_security_analysis_html(
            passive_data=passive_data,
            findings=findings,
            scan_duration=scan_duration,
            total_hosts=len(raw_results),
        )

        if hasattr(self, '_sec_progress') and self._sec_progress:
            self._sec_progress.close()

        report_dir = str(config.db_path) + '/ai_report'

        try:
            os.makedirs(report_dir, exist_ok=True)
            test_file = report_dir + '/.write_test'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except (PermissionError, OSError):
            report_dir = '/tmp/batchRun/ai_report'
            os.makedirs(report_dir, exist_ok=True)

        output_file = (report_dir + '/security_analysis_'
                       + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.html')

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        QMessageBox.information(
            self, 'Security Analysis',
            f'安全分析完成（耗时 {scan_duration:.1f} 秒），点击确定后在浏览器中打开报告。\n\n'
            f'报告路径：\n{output_file}'
        )
        webbrowser.open('file://' + output_file)

    def _collect_passive_security_data(self):
        """Collect security-relevant findings from existing in-memory data."""
        data = {}

        host_ip_set = set(self.host_list_class.host_ip_dic.keys())
        network_ip_set = set()
        network_ip_info = {}

        for zone in self.network_scan_dic:
            for network in self.network_scan_dic[zone]:
                for ip in self.network_scan_dic[zone][network]:
                    network_ip_set.add(ip)
                    network_ip_info[ip] = {'zone': zone, 'network': network}

        data['unregistered_ips'] = sorted(network_ip_set - host_ip_set)
        data['network_ip_info'] = network_ip_info

        non_standard_ssh = []

        for ip, info in self.host_list_class.host_ip_dic.items():
            port = info.get('ssh_port', 22) or 22

            try:
                port = int(port)
            except (ValueError, TypeError):
                port = 22

            if port != 22:
                non_standard_ssh.append((ip, port))

        data['non_standard_ssh'] = non_standard_ssh

        os_dist = {}

        for ip, info in self.host_info_dic.items():
            os_name = info.get('os', 'Unknown') or 'Unknown'
            os_dist.setdefault(os_name, []).append(ip)

        data['os_distribution'] = os_dist

        eol_os = {}

        for os_name, ips in os_dist.items():
            for pattern, label in EOL_OS_PATTERNS:
                if pattern.search(os_name):
                    eol_os.setdefault(label, []).extend(ips)
                    break

        data['eol_os'] = eol_os

        host_stat_file = str(config.db_path) + '/host_stat/host_stat.json'
        stat_dic = self.get_stat_info(host_stat_file) if os.path.exists(host_stat_file) else {}

        recent_reboot = []
        long_uptime = []

        for ip, stat in stat_dic.items():
            up_days = stat.get('up_days', -1)

            try:
                up_days = int(up_days)
            except (ValueError, TypeError):
                continue

            if up_days == 0:
                recent_reboot.append((ip, stat))
            elif up_days > 365:
                long_uptime.append((ip, stat))

        data['recent_reboot'] = recent_reboot
        data['long_uptime'] = long_uptime

        return data

    def _parse_security_scan_results(self, raw_results):
        """Parse raw SSH output from all hosts into structured findings."""
        findings = {}

        for ip, raw in raw_results.items():
            host_findings = {
                'ssh_config': {},
                'uid0_accounts': [],
                'login_accounts': [],
                'failed_logins': 0,
                'listening_ports': [],
                'suid_files': [],
                'world_writable': [],
                'crontab_entries': [],
                'cron_d_files': [],
                'firewall_status': 'unknown',
                'firewall_rules': '',
                'kernel_security': {},
                'sensitive_files': [],
                'last_logins': [],
                'security_tools': [],
                'zombie_count': 0,
                'boot_time': '',
                'scan_error': '',
                'permission_denied_sections': [],
            }

            if not raw or raw.startswith('ERROR:') or '===END===' not in raw:
                if not raw:
                    host_findings['scan_error'] = 'No output received'
                elif raw.startswith('ERROR:'):
                    host_findings['scan_error'] = raw
                elif 'Timeout' in raw or 'pexpect' in raw:
                    host_findings['scan_error'] = 'SSH连接超时'
                elif 'Permission denied' in raw or 'password' in raw.lower():
                    host_findings['scan_error'] = 'SSH认证失败（权限不足）'
                elif 'Connection refused' in raw:
                    host_findings['scan_error'] = 'SSH连接被拒绝'
                elif 'No route to host' in raw or 'Network is unreachable' in raw:
                    host_findings['scan_error'] = '网络不可达'
                else:
                    host_findings['scan_error'] = raw[:100] if len(raw) > 100 else (raw or '未知错误')

                findings[ip] = host_findings
                continue

            sections = {}
            current_section = None
            current_lines = []

            for line in raw.split('\n'):
                stripped = line.strip()

                if stripped.startswith('===') and stripped.endswith('===') and len(stripped) > 6:
                    if current_section:
                        sections[current_section] = current_lines
                    current_section = stripped.strip('=')
                    current_lines = []
                else:
                    current_lines.append(line)

            if current_section:
                sections[current_section] = current_lines

            # Parse SSHD_CONFIG
            if 'SSHD_CONFIG' in sections:
                lines = sections['SSHD_CONFIG']
                content = '\n'.join(lines)

                if 'PERMISSION_DENIED' in content:
                    host_findings['permission_denied_sections'].append('SSHD_CONFIG')
                else:
                    for line in lines:
                        line = line.strip()

                        if line.startswith('#') or not line:
                            continue

                        parts = line.split(None, 1)

                        if len(parts) == 2:
                            key, val = parts[0].lower(), parts[1]

                            if key == 'permitrootlogin':
                                host_findings['ssh_config']['PermitRootLogin'] = val
                            elif key == 'passwordauthentication':
                                host_findings['ssh_config']['PasswordAuthentication'] = val
                            elif key == 'maxauthtries':
                                host_findings['ssh_config']['MaxAuthTries'] = val
                            elif key == 'x11forwarding':
                                host_findings['ssh_config']['X11Forwarding'] = val
                            elif key == 'permitemptypasswords':
                                host_findings['ssh_config']['PermitEmptyPasswords'] = val

            # Parse PASSWD_AUDIT
            if 'PASSWD_AUDIT' in sections:
                for line in sections['PASSWD_AUDIT']:
                    line = line.strip()

                    if not line:
                        continue

                    parts = line.split(':')

                    if len(parts) >= 3:
                        username, uid_str, shell = parts[0], parts[1], parts[2]

                        try:
                            uid = int(uid_str)
                        except (ValueError, TypeError):
                            continue

                        if uid == 0 and username != 'root':
                            host_findings['uid0_accounts'].append(username)

                        nologin_shells = ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']

                        if uid >= 1000 and shell not in nologin_shells:
                            host_findings['login_accounts'].append((username, uid, shell))

            # Parse FAILED_LOGINS
            if 'FAILED_LOGINS' in sections:
                numbers = []

                for line in sections['FAILED_LOGINS']:
                    line = line.strip()

                    try:
                        numbers.append(int(line))
                    except (ValueError, TypeError):
                        pass

                host_findings['failed_logins'] = max(numbers) if numbers else 0

            # Parse LISTENING_PORTS
            if 'LISTENING_PORTS' in sections:
                content = '\n'.join(sections['LISTENING_PORTS'])

                if 'PERMISSION_DENIED' in content:
                    host_findings['permission_denied_sections'].append('LISTENING_PORTS')
                else:
                    for line in sections['LISTENING_PORTS']:
                        line = line.strip()

                        if not line or line.startswith('State') or line.startswith('Netid'):
                            continue

                        parts = line.split()

                        if len(parts) >= 4:
                            local_addr = parts[3] if len(parts) > 3 else ''
                            process = parts[-1] if len(parts) >= 6 else ''

                            if ':' in local_addr:
                                addr_part, port_part = local_addr.rsplit(':', 1)

                                try:
                                    port = int(port_part)
                                except (ValueError, TypeError):
                                    continue

                                host_findings['listening_ports'].append({
                                    'address': addr_part,
                                    'port': port,
                                    'process': process,
                                })

            # Parse SUID_SGID (only non-standard directories are scanned)
            if 'SUID_SGID' in sections:
                for line in sections['SUID_SGID']:
                    filepath = line.strip()

                    if filepath and filepath.startswith('/'):
                        host_findings['suid_files'].append(filepath)

            # Parse WORLD_WRITABLE
            if 'WORLD_WRITABLE' in sections:
                for line in sections['WORLD_WRITABLE']:
                    line = line.strip()

                    if line and not line.startswith('total'):
                        host_findings['world_writable'].append(line)

            # Parse CRONTAB
            if 'CRONTAB' in sections:
                for line in sections['CRONTAB']:
                    stripped = line.strip()

                    if not stripped or not stripped.startswith('USER_CRON|'):
                        continue

                    parts = stripped.split('|', 2)

                    if len(parts) == 3:
                        cron_user = parts[1]
                        cron_line = parts[2]
                        fields = cron_line.split(None, 5)

                        if len(fields) >= 6:
                            schedule = ' '.join(fields[:5])
                            command = fields[5]
                        else:
                            schedule = cron_line
                            command = ''

                        host_findings['crontab_entries'].append({
                            'user': cron_user,
                            'schedule': schedule,
                            'command': command,
                        })

            # Parse FIREWALL (skipped - not applicable for internal HPC clusters)

            # Parse KERNEL_SECURITY
            if 'KERNEL_SECURITY' in sections:
                for line in sections['KERNEL_SECURITY']:
                    line = line.strip()

                    if line.startswith('ip_forward='):
                        host_findings['kernel_security']['ip_forward'] = line.split('=', 1)[1]
                    elif line.startswith('aslr='):
                        host_findings['kernel_security']['aslr'] = line.split('=', 1)[1]

            # Parse SENSITIVE_FILES
            if 'SENSITIVE_FILES' in sections:
                content = '\n'.join(sections['SENSITIVE_FILES'])

                if 'PERMISSION_DENIED' in content:
                    host_findings['permission_denied_sections'].append('SENSITIVE_FILES')
                else:
                    for line in sections['SENSITIVE_FILES']:
                        parts = line.strip().split()

                        if len(parts) >= 4:
                            host_findings['sensitive_files'].append({
                                'perms': parts[0],
                                'owner': parts[1],
                                'group': parts[2],
                                'path': parts[3],
                            })

            # Parse LAST_LOGINS
            if 'LAST_LOGINS' in sections:
                for line in sections['LAST_LOGINS']:
                    if line.strip() and not line.startswith('wtmp') and not line.startswith('btmp'):
                        host_findings['last_logins'].append(line.strip())

            # Parse SECURITY_TOOLS
            if 'SECURITY_TOOLS' in sections:
                for line in sections['SECURITY_TOOLS']:
                    line = line.strip()

                    if line and 'not found' not in line:
                        host_findings['security_tools'].append(line)

            # Parse ZOMBIE_PROCS
            if 'ZOMBIE_PROCS' in sections:
                for line in sections['ZOMBIE_PROCS']:
                    try:
                        host_findings['zombie_count'] = int(line.strip())
                        break
                    except (ValueError, TypeError):
                        pass

            # Parse BOOT_TIME
            if 'BOOT_TIME' in sections:
                for line in sections['BOOT_TIME']:
                    line = line.strip()

                    if line:
                        if 'system boot' in line:
                            parts = line.split('system boot')
                            if len(parts) > 1:
                                host_findings['boot_time'] = parts[1].strip()
                        else:
                            host_findings['boot_time'] = line

                        break

            findings[ip] = host_findings

        return findings

    def _build_security_analysis_html(self, **kwargs):
        """Build HTML security analysis report - organized by risk domain."""
        passive_data = kwargs['passive_data']
        findings = kwargs['findings']
        scan_duration = kwargs['scan_duration']
        total_hosts = kwargs['total_hosts']

        def get_host_name(ip):
            info = self.host_list_class.host_ip_dic.get(ip, {})
            names = info.get('host_name', [])
            return names[0] if names else ''

        def get_host_groups(ip):
            info = self.host_list_class.host_ip_dic.get(ip, {})
            groups = info.get('groups', [])
            return ', '.join(groups) if groups else ''

        def get_server_type(ip):
            info = self.host_info_dic.get(ip, {})
            return info.get('server_type', '')

        # === Pre-compute all findings for dashboard and sections ===
        non_standard_ssh = passive_data.get('non_standard_ssh', [])
        os_dist = passive_data.get('os_distribution', {})
        eol_os = passive_data.get('eol_os', {})
        total_eol = sum(len(ips) for ips in eol_os.values())

        ssh_issues = []
        for ip, f in findings.items():
            if f.get('scan_error') or 'SSHD_CONFIG' in f.get('permission_denied_sections', []):
                continue
            cfg = f.get('ssh_config', {})
            if not cfg:
                continue
            risk_items = []
            if cfg.get('PermitEmptyPasswords', '').lower() == 'yes':
                risk_items.append('PermitEmptyPasswords=yes')
            if cfg.get('PasswordAuthentication', '').lower() == 'yes':
                risk_items.append('PasswordAuthentication=yes')
            try:
                if int(cfg.get('MaxAuthTries', 6)) > 6:
                    risk_items.append(f'MaxAuthTries={cfg["MaxAuthTries"]}')
            except (ValueError, TypeError):
                pass
            if risk_items:
                ssh_issues.append((ip, cfg, risk_items))

        uid0_hosts = [(ip, f['uid0_accounts']) for ip, f in findings.items() if f.get('uid0_accounts')]
        high_failed = [(ip, f['failed_logins']) for ip, f in findings.items() if f.get('failed_logins', 0) > 20]

        risky_ports = {6379: 'Redis', 3306: 'MySQL', 27017: 'MongoDB', 9200: 'Elasticsearch',
                       5432: 'PostgreSQL', 11211: 'Memcached', 2379: 'etcd', 8080: 'HTTP-ALT'}
        exposed_services = []
        for ip, f in findings.items():
            if f.get('scan_error'):
                continue
            for port_info in f.get('listening_ports', []):
                port = port_info.get('port', 0)
                addr = port_info.get('address', '')
                if port in risky_ports and addr not in ('127.0.0.1', '::1', 'localhost', '[::1]'):
                    exposed_services.append((ip, port, risky_ports[port], addr, port_info.get('process', '')))

        suid_hosts = [(ip, f['suid_files']) for ip, f in findings.items() if f.get('suid_files')]
        bad_perms_hosts = []
        for ip, f in findings.items():
            bad_files = []
            for file_info in f.get('sensitive_files', []):
                path = file_info.get('path', '')
                perms = file_info.get('perms', '')
                if 'shadow' in path and perms not in ('0', '000', '640', '600'):
                    bad_files.append(file_info)
                elif path == '/etc/passwd' and perms not in ('644', '44'):
                    bad_files.append(file_info)
            if bad_files:
                bad_perms_hosts.append((ip, bad_files))

        suspicious_patterns = ['wget ', 'curl ', '/tmp/', 'base64', 'eval ', 'python -c',
                               'bash -i', '/dev/tcp', 'nc ', 'ncat ']
        suspicious_cron_hosts = []
        for ip, f in findings.items():
            suspicious_entries = []
            for entry in f.get('crontab_entries', []):
                cmd_str = entry.get('command', '') if isinstance(entry, dict) else entry
                if any(p in cmd_str.lower() for p in suspicious_patterns):
                    suspicious_entries.append(entry)
            if suspicious_entries:
                suspicious_cron_hosts.append((ip, suspicious_entries))

        kernel_issues = []
        for ip, f in findings.items():
            if f.get('scan_error'):
                continue
            ks = f.get('kernel_security', {})
            issues = []
            if ks.get('ip_forward') == '1':
                issues.append('IP转发已开启')
            if ks.get('aslr') in ('0', '1'):
                issues.append(f'ASLR未完全启用(值={ks.get("aslr")})')
            if issues:
                kernel_issues.append((ip, ks, issues))

        no_tools_hosts = [ip for ip, f in findings.items()
                          if not f.get('scan_error') and not f.get('security_tools')]

        # Risk scoring
        per_host_scores = {}
        for ip, f in findings.items():
            if f.get('scan_error'):
                per_host_scores[ip] = -1
                continue
            score = 0
            cfg = f.get('ssh_config', {})
            if cfg.get('PermitEmptyPasswords', '').lower() == 'yes':
                score += 3
            if f.get('uid0_accounts'):
                score += 3
            if f.get('kernel_security', {}).get('aslr') == '0':
                score += 3
            if f.get('kernel_security', {}).get('ip_forward') == '1':
                score += 1
            if f.get('failed_logins', 0) > 100:
                score += 1
            if f.get('suid_files'):
                score += 1
            per_host_scores[ip] = score

        high_risk = [(ip, s) for ip, s in per_host_scores.items() if s >= 6]
        medium_risk = [(ip, s) for ip, s in per_host_scores.items() if 3 <= s < 6]
        low_risk = [(ip, s) for ip, s in per_host_scores.items() if 0 <= s < 3]

        lines = []

        # === CSS ===
        css = '''
body { background: #1B2631; color: #D5D8DC; font-family: "Microsoft YaHei", "Segoe UI", sans-serif; margin: 0; padding: 0; display: flex; }
nav { position: fixed; top: 0; left: 0; width: 210px; height: 100%; background: #17202A; border-right: 1px solid #2C3E50; padding: 15px 10px; overflow-y: auto; box-sizing: border-box; }
nav h3 { color: #5DADE2; font-size: 14px; margin-bottom: 10px; border-bottom: none; }
nav a { display: block; color: #ABB2B9; text-decoration: none; padding: 5px 8px; font-size: 12px; border-radius: 3px; margin: 1px 0; }
nav a:hover { background: #2C3E50; color: #F0F0F0; }
nav .nav-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
nav .dot-red { background: #E74C3C; }
nav .dot-yellow { background: #F39C12; }
nav .dot-green { background: #2ECC71; }
nav .nav-section { font-weight: bold; color: #D5D8DC; padding: 8px 8px 4px; margin-top: 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
main { margin-left: 230px; padding: 25px 35px; flex: 1; min-width: 0; }
h2 { color: #5DADE2; border-bottom: 2px solid #2C3E50; padding-bottom: 8px;
     position: sticky; top: 0; margin: 0 -35px; padding: 12px 35px;
     background: #1B2631; z-index: 100; }
h3 { color: #5DADE2; border-bottom: 1px solid #2C3E50; padding-bottom: 6px; margin-top: 28px; scroll-margin-top: 50px; }
h4 { color: #48C9B0; margin-top: 15px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { border: 1px solid #4A4A4A; padding: 5px 10px; text-align: left; font-size: 13px; }
th { background: #2C3E50; color: #AED6F1; cursor: pointer; user-select: none; white-space: nowrap; }
th.sortable:hover { background: #34495E; }
th.sortable::after { content: " \\2195"; font-size: 10px; color: #666; }
td { background: #1E2A35; }
tr:hover td { background: #263545; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; margin-right: 6px; }
.badge-danger { background: #641E16; color: #F1948A; }
.badge-warning { background: #7D6608; color: #F9E79F; }
.badge-ok { background: #1E8449; color: #ABEBC6; }
.badge-security { background: #4A1A6B; color: #D2B4DE; }
.badge-config { background: #0E4B5A; color: #76D7C4; }
.badge-info { background: #1A3A4A; color: #85C1E9; }
.badge-resource { background: #4A3000; color: #F0B27A; }
.ok { color: #2ECC71; font-size: 13px; }
.missing { color: #95A5A6; font-style: italic; }
.risk-box { background: #2C1010; border: 2px solid #E74C3C; border-radius: 8px; padding: 15px 20px; margin: 15px 0; }
.warn-box { background: #2C2410; border: 2px solid #F39C12; border-radius: 8px; padding: 15px 20px; margin: 15px 0; }
.conclusion-box { background: #1E2A35; border: 1px solid #34495E; border-radius: 8px; padding: 12px 18px; margin: 10px 0; }
.risk-item { padding: 6px 0; border-bottom: 1px solid #2C3E50; font-size: 13px; }
.risk-item:last-child { border-bottom: none; }
.collapse-wrap { position: relative; }
.row-toggle { display: none; }
.collapse-wrap tr.extra { display: none; }
.row-toggle:checked ~ table tr.extra { display: table-row; }
tfoot td { padding: 0; border-top: 1px solid #4A4A4A; border-bottom: none; }
.more-toggle { display: block; cursor: pointer; user-select: none; text-align: center; font-size: 13px; color: #5DADE2; font-weight: 600; padding: 9px 12px; background: #2C3E50; }
.more-toggle:hover { background: #34495E; }
.more-toggle .ico { color: #95A5A6; margin-right: 4px; }
.more-toggle .hide { display: none; }
.row-toggle:checked ~ table .more-toggle .show { display: none; }
.row-toggle:checked ~ table .more-toggle .hide { display: inline; }
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 15px 0; }
.dash-card { background: #1E2A35; border: 1px solid #34495E; border-radius: 8px; padding: 12px 15px; text-align: center; }
.dash-card .num { font-size: 26px; font-weight: bold; margin: 4px 0; }
.dash-card .label { font-size: 11px; color: #ABB2B9; }
.dash-card.danger { border-color: #E74C3C; }
.dash-card.danger .num { color: #E74C3C; }
.dash-card.warning { border-color: #F39C12; }
.dash-card.warning .num { color: #F39C12; }
.dash-card.ok .num { color: #2ECC71; }
.dash-card.info .num { color: #5DADE2; }
'''

        # Sort JavaScript
        sort_js = '''
document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll("th.sortable").forEach(function(th) {
        th.addEventListener("click", function() {
            var table = th.closest("table");
            var idx = Array.from(th.parentNode.children).indexOf(th);
            var tbody = table.querySelector("tbody") || table;
            var rows = Array.from(tbody.querySelectorAll("tr")).filter(function(r) { return !r.querySelector("th"); });
            var asc = th.dataset.asc !== "1";
            th.dataset.asc = asc ? "1" : "0";
            rows.sort(function(a, b) {
                var at = (a.children[idx] || {}).textContent || "";
                var bt = (b.children[idx] || {}).textContent || "";
                var an = parseFloat(at), bn = parseFloat(bt);
                if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
                return asc ? at.localeCompare(bt) : bt.localeCompare(at);
            });
            var limit = 10;
            rows.forEach(function(r, i) {
                tbody.appendChild(r);
                if (rows.length > limit) {
                    if (i >= limit) r.classList.add("extra"); else r.classList.remove("extra");
                }
            });
        });
    });
});
'''

        lines.append('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">')
        lines.append('<title>安全分析报告 - batchRun</title>')
        lines.append(f'<style>{css}</style>')
        lines.append('</head><body>')
        lines.append(f'<script>{sort_js}</script>')

        # Helper: nav dot color
        def nav_dot(count):
            if count > 0:
                return '<span class="nav-dot dot-red"></span>'
            return '<span class="nav-dot dot-green"></span>'

        # Navigation sidebar with status dots
        lines.append('<nav>')
        lines.append('<h3>目录导航</h3>')
        lines.append(f'<a href="#sec-sshd">{nav_dot(len(ssh_issues))}1. SSH配置审计</a>')
        lines.append(f'<a href="#sec-accounts">{nav_dot(len(uid0_hosts) + len(high_failed))}2. 账户安全</a>')
        lines.append(f'<a href="#sec-ports">{nav_dot(len(exposed_services))}3. 端口暴露</a>')
        lines.append(f'<a href="#sec-filesystem">{nav_dot(len(suid_hosts) + len(bad_perms_hosts))}4. 文件权限</a>')
        lines.append(f'<a href="#sec-kernel">{nav_dot(len(kernel_issues))}5. 内核参数</a>')
        lines.append(f'<a href="#sec-cron">{nav_dot(len(suspicious_cron_hosts))}6. 定时任务</a>')
        lines.append(f'<a href="#sec-os">{nav_dot(total_eol)}7. OS版本</a>')
        lines.append(f'<a href="#sec-tools">{nav_dot(len(no_tools_hosts))}8. 安全工具</a>')
        lines.append('<a href="#sec-actions">整改建议</a>')
        lines.append('</nav>')

        lines.append('<main>')

        # Collapsible table helper (same style as Cluster Analysis)
        collapse_id = [0]

        def collapsible_table(headers, rows, collapse_limit=10):
            limit = collapse_limit
            col_count = len(headers)
            th_row = '<tr>' + ''.join(f'<th class="sortable">{h}</th>' for h in headers) + '</tr>'

            visible_rows = []
            hidden_rows = []

            for i, row in enumerate(rows):
                tr = '<tr>' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>'

                if i < limit:
                    visible_rows.append(tr)
                else:
                    hidden_rows.append(tr.replace('<tr>', '<tr class="extra">', 1))

            if not hidden_rows:
                html_parts = [f'<table><thead>{th_row}</thead><tbody>']
                html_parts.extend(visible_rows)
                html_parts.append('</tbody></table>')
                return '\n'.join(html_parts)

            collapse_id[0] += 1
            cid = f'tbl-{collapse_id[0]}'

            html_parts = ['<div class="collapse-wrap">']
            html_parts.append(f'<input type="checkbox" id="{cid}" class="row-toggle">')
            html_parts.append(f'<table data-collapse="{limit}"><thead>{th_row}</thead><tbody>')
            html_parts.extend(visible_rows)
            html_parts.extend(hidden_rows)
            html_parts.append('</tbody>')
            html_parts.append(f'<tfoot><tr><td colspan="{col_count}">'
                              f'<label class="more-toggle" for="{cid}">'
                              f'<span class="ico">&#9656;</span>'
                              f'<span class="show">展开其余 {len(hidden_rows)} 行</span>'
                              f'<span class="ico hide">&#9662;</span>'
                              f'<span class="hide">收起</span>'
                              f'</label></td></tr></tfoot>')
            html_parts.append('</table>')
            html_parts.append('</div>')
            return '\n'.join(html_parts)

        def section_pass(msg='未发现异常'):
            return f'<p class="ok">✔ {msg}</p>'

        # === DASHBOARD ===
        lines.append('<h2 id="sec-dashboard" style="margin-top:0">安全分析报告</h2>')
        lines.append(f'<p style="color:#ABB2B9;font-size:12px;margin:-5px 0 10px">'
                     f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | '
                     f'用户: {CURRENT_USER} | 耗时: {scan_duration:.1f}s</p>')

        lines.append('<div class="dashboard">')
        lines.append(f'<div class="dash-card info"><div class="num">{total_hosts}</div><div class="label">扫描主机</div></div>')

        card_cls = 'danger' if high_risk else 'ok'
        lines.append(f'<div class="dash-card {card_cls}"><div class="num">{len(high_risk)}</div><div class="label">高危主机</div></div>')

        card_cls = 'warning' if medium_risk else 'ok'
        lines.append(f'<div class="dash-card {card_cls}"><div class="num">{len(medium_risk)}</div><div class="label">中危主机</div></div>')

        lines.append(f'<div class="dash-card ok"><div class="num">{len(low_risk)}</div><div class="label">低危/安全</div></div>')

        total_issues = (len(ssh_issues) + len(uid0_hosts) + len(exposed_services)
                        + len(bad_perms_hosts) + len(kernel_issues))
        card_cls = 'danger' if total_issues > 10 else ('warning' if total_issues > 0 else 'ok')
        lines.append(f'<div class="dash-card {card_cls}"><div class="num">{total_issues}</div><div class="label">安全发现</div></div>')
        lines.append('</div>')

        # === SECTION: 1. SSH配置审计 ===
        lines.append('<h3 id="sec-sshd">1. SSH配置审计</h3>')

        if ssh_issues:
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-danger">高危</span>'
                         f'<b>{len(ssh_issues)}</b> 台主机SSH配置存在风险项。</p></div>')
            rows = []

            for ip, cfg, risk_items in ssh_issues:
                rows.append([
                    ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                    cfg.get('PasswordAuthentication', 'N/A'),
                    cfg.get('PermitEmptyPasswords', 'N/A'),
                    cfg.get('MaxAuthTries', 'N/A'),
                    '; '.join(risk_items),
                ])

            lines.append(collapsible_table(
                ['IP', '主机名', '服务器类型', '分组', 'PasswordAuth', 'PermitEmpty', 'MaxAuthTries', '风险项'], rows))
        else:
            lines.append(section_pass('已扫描主机的SSH配置未发现高风险项'))

        if non_standard_ssh:
            lines.append('<h4>非标准SSH端口</h4>')
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-config">配置</span>'
                         f'<b>{len(non_standard_ssh)}</b> 台主机使用非标准SSH端口（非22），'
                         f'需确认是安全加固措施还是配置异常。</p></div>')
            rows = []

            for ip, port in non_standard_ssh:
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip), str(port)])

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', 'SSH端口'], rows))

        lines.append('<h3 id="sec-accounts">2. 账户安全</h3>')

        if uid0_hosts:
            lines.append('<h4>UID=0 非root账户</h4>')
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-danger">高危</span>'
                         f'<b>{len(uid0_hosts)}</b> 台主机存在非root的UID=0账户，'
                         f'这是严重的安全隐患（可能是后门账户）。</p></div>')
            rows = []

            for ip, accounts in uid0_hosts:
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip), ', '.join(accounts)])

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', 'UID=0账户'], rows))

        if high_failed:
            lines.append('<h4>暴力破解痕迹</h4>')
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-warning">关注</span>'
                         f'<b>{len(high_failed)}</b> 台主机近期SSH登录失败超过20次，'
                         f'可能遭受暴力破解攻击。</p></div>')
            rows = []

            for ip, count in sorted(high_failed, key=lambda x: -x[1]):
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip), str(count)])

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '失败次数'], rows))

        if not uid0_hosts and not high_failed:
            lines.append(section_pass('未发现账户安全异常'))

        # === SECTION: 3. 端口暴露 ===
        lines.append('<h3 id="sec-ports">3. 端口暴露</h3>')

        if exposed_services:
            lines.append('<h4>高危端口暴露</h4>')
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-danger">高危</span>'
                         f'发现 <b>{len(exposed_services)}</b> 个高风险服务绑定在非本地地址上，'
                         f'可能导致数据泄露或未授权访问。</p></div>')
            rows = []

            for ip, port, svc, addr, proc in exposed_services:
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                             str(port), svc, addr, proc])

            lines.append(collapsible_table(
                ['IP', '主机名', '服务器类型', '分组', '端口', '服务', '绑定地址', '进程'], rows))

        if not exposed_services:
            lines.append(section_pass('未发现高危端口暴露'))

        # === SECTION: 系统加固 ===
        lines.append('<h3 id="sec-filesystem">4. 文件权限</h3>')

        if suid_hosts:
            lines.append('<h4>异常位置SUID/SGID文件</h4>')
            total_files = sum(len(files) for _, files in suid_hosts)
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-danger">高危</span>'
                         f'<b>{len(suid_hosts)}</b> 台主机在非系统目录'
                         f'（/tmp, /home, /opt, /usr/local等）发现 <b>{total_files}</b> 个'
                         f'SUID/SGID文件，疑似提权后门。</p></div>')
            rows = []

            for ip, files in suid_hosts:
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                             str(len(files)), '<br>'.join(files)])

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '数量', '文件列表'], rows))

        if bad_perms_hosts:
            lines.append('<h4>敏感文件权限异常</h4>')
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-danger">高危</span>'
                         f'<b>{len(bad_perms_hosts)}</b> 台主机敏感文件权限设置不当，'
                         f'可能导致密码哈希泄露。</p></div>')
            rows = []

            for ip, files in bad_perms_hosts:
                for fi in files:
                    rows.append([ip, get_host_name(ip), fi['path'], fi['perms'], fi['owner'], fi['group']])

            lines.append(collapsible_table(['IP', '主机名', '文件路径', '权限', '属主', '属组'], rows))

        if not suid_hosts and not bad_perms_hosts:
            lines.append(section_pass('文件系统安全检查未发现异常'))

        lines.append('<h3 id="sec-kernel">5. 内核参数</h3>')

        if kernel_issues:
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-warning">关注</span>'
                         f'<b>{len(kernel_issues)}</b> 台主机内核安全参数配置不当。</p></div>')
            rows = []

            for ip, ks, issues in kernel_issues:
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                             ks.get('ip_forward', 'N/A'), ks.get('aslr', 'N/A'), '; '.join(issues)])

            lines.append(collapsible_table(
                ['IP', '主机名', '服务器类型', '分组', 'ip_forward', 'ASLR', '问题'], rows))
        else:
            lines.append(section_pass('内核安全参数配置正常'))

        lines.append('<h3 id="sec-cron">6. 定时任务</h3>')

        # Full crontab inventory table.
        all_cron_rows = []
        for ip, f in findings.items():
            for entry in f.get('crontab_entries', []):
                if isinstance(entry, dict):
                    safe_cmd = entry.get('command', '').replace('<', '&lt;').replace('>', '&gt;')
                    all_cron_rows.append([
                        ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                        entry.get('user', ''), entry.get('schedule', ''), safe_cmd,
                    ])

        if all_cron_rows:
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-info">统计</span>'
                         f'共采集到 <b>{len(all_cron_rows)}</b> 条定时任务（来自 '
                         f'<b>{sum(1 for _, f in findings.items() if f.get("crontab_entries"))}</b> 台主机）。</p></div>')
            lines.append(collapsible_table(
                ['IP', '主机名', '服务器类型', '分组', '任务用户', '定时频率', '执行命令'],
                all_cron_rows))
        else:
            lines.append(section_pass('未采集到定时任务'))

        # Suspicious crontab entries.
        if suspicious_cron_hosts:
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-warning">关注</span>'
                         f'<b>{len(suspicious_cron_hosts)}</b> 台主机定时任务中包含可疑命令模式'
                         f'（wget/curl/base64/eval/反弹shell等）。</p></div>')
            rows = []

            for ip, entries in suspicious_cron_hosts:
                for entry in entries:
                    if isinstance(entry, dict):
                        safe_cmd = entry.get('command', '').replace('<', '&lt;').replace('>', '&gt;')
                        rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                                     entry.get('user', ''), entry.get('schedule', ''), safe_cmd])
                    else:
                        safe_entry = entry.replace('<', '&lt;').replace('>', '&gt;')
                        rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip),
                                     '', '', safe_entry])

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '任务用户', '定时频率', '可疑命令'], rows))

        # === SECTION: 7. OS版本 ===
        lines.append('<h3 id="sec-os">7. OS版本</h3>')

        if eol_os:
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-danger">高危</span>'
                         f'发现 <b>{total_eol}</b> 台主机运行已停止维护(EOL)的操作系统，'
                         f'不再获得安全补丁更新。</p></div>')

        if os_dist:
            rows = []

            for os_name, ips in sorted(os_dist.items(), key=lambda x: -len(x[1])):
                eol_label = ''

                for pattern, label in EOL_OS_PATTERNS:
                    if pattern.search(os_name):
                        eol_label = '<span class="badge badge-danger">EOL</span>'
                        break

                rows.append([os_name, str(len(ips)), eol_label])

            lines.append(collapsible_table(['操作系统', '主机数', 'EOL状态'], rows))
        else:
            lines.append('<p class="missing">无host_info数据，无法分析OS分布。</p>')

        # === SECTION: 8. 安全工具 ===
        lines.append('<h3 id="sec-tools">8. 安全工具</h3>')

        if no_tools_hosts:
            lines.append(f'<div class="conclusion-box"><p><span class="badge badge-warning">信息</span>'
                         f'<b>{len(no_tools_hosts)}</b> 台主机未检测到主机级安全加固工具'
                         f'（SELinux/AppArmor/fail2ban），建议按需评估是否启用。</p></div>')
            rows = []

            for ip in no_tools_hosts:
                rows.append([ip, get_host_name(ip), get_server_type(ip), get_host_groups(ip), '无'])

            lines.append(collapsible_table(['IP', '主机名', '服务器类型', '分组', '安全工具'], rows))
        else:
            lines.append(section_pass('所有主机均已部署安全工具'))

        # === SECTION: 整改建议 ===
        lines.append('<h3 id="sec-actions">整改建议</h3>')

        # High risk host list
        if high_risk:
            lines.append('<h4>高危主机</h4>')
            lines.append('<div class="risk-box">')

            for ip, score in sorted(high_risk, key=lambda x: -x[1])[:20]:
                f = findings[ip]
                issues = []
                cfg = f.get('ssh_config', {})

                if cfg.get('PermitEmptyPasswords', '').lower() == 'yes':
                    issues.append('允许空密码登录')

                if f.get('uid0_accounts'):
                    issues.append(f'UID=0后门账户: {",".join(f["uid0_accounts"])}')

                if f.get('kernel_security', {}).get('aslr') == '0':
                    issues.append('ASLR已禁用')

                lines.append(f'<div class="risk-item"><span class="badge badge-danger">高危</span>'
                             f'<b>{ip}</b> ({get_host_name(ip)}) — {"; ".join(issues)}</div>')

            lines.append('</div>')

        # Prioritized action items
        lines.append('<h4>优先整改事项</h4>')
        lines.append('<div class="conclusion-box" style="border-color: #5B7B9D;">')
        actions = []

        if uid0_hosts:
            actions.append(f'<span class="badge badge-danger">紧急</span>'
                           f'立即排查 {len(uid0_hosts)} 台主机上的UID=0非root账户（疑似后门）')

        if exposed_services:
            actions.append(f'<span class="badge badge-danger">紧急</span>'
                           f'修复 {len(exposed_services)} 个高危服务端口暴露，限制绑定到127.0.0.1或配置防火墙规则')

        if ssh_issues:
            empty_pw_count = sum(1 for _, _, r in ssh_issues if 'PermitEmptyPasswords=yes' in r)

            if empty_pw_count:
                actions.append(f'<span class="badge badge-danger">紧急</span>'
                               f'{empty_pw_count} 台主机允许空密码登录，需立即关闭PermitEmptyPasswords')

        if kernel_issues:
            actions.append(f'<span class="badge badge-config">配置</span>'
                           f'{len(kernel_issues)} 台主机需调整内核参数'
                           f'（关闭ip_forward、启用ASLR: kernel.randomize_va_space=2）')

        if total_eol:
            actions.append(f'<span class="badge badge-resource">运维</span>'
                           f'{total_eol} 台EOL操作系统主机需规划升级/替换，不再获得安全补丁')

        if high_failed:
            actions.append(f'<span class="badge badge-resource">运维</span>'
                           f'{len(high_failed)} 台主机遭受暴力破解，建议部署fail2ban并检查来源IP')

        if no_tools_hosts:
            actions.append(f'<span class="badge badge-resource">参考</span>'
                           f'{len(no_tools_hosts)} 台主机未启用主机级安全加固（SELinux/AppArmor/fail2ban），可按需评估')

        if not actions:
            actions.append('<span class="badge badge-ok">无</span>当前安全状态良好，建议保持定期扫描监控。')

        for action in actions:
            lines.append(f'<div class="risk-item">{action}</div>')

        lines.append('</div>')

        lines.append('</main>')
        lines.append('</body></html>')

        return '\n'.join(lines)

# For AI Menu (end) #

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
        if hasattr(self, 'ai_thread') and self.ai_thread and self.ai_thread.isRunning():
            self.ai_thread.stop()
            self.ai_thread.wait(3000)

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


class SshTestThread(QThread):
    """Worker thread for SSH accessibility testing via uptime -s."""
    progress_signal = pyqtSignal(int, int, str)
    finished_signal = pyqtSignal(dict)

    def __init__(self, host_ip_set, tmp_dir):
        super().__init__()
        self.host_ip_set = host_ip_set
        self.tmp_dir = tmp_dir
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def run(self):
        import shutil

        try:
            total = len(self.host_ip_set)
            host_list_file = self.tmp_dir + '/test_hosts.list'
            output_dir = self.tmp_dir + '/output'
            os.makedirs(output_dir, exist_ok=True)

            with open(host_list_file, 'w') as f:
                for ip in sorted(self.host_ip_set):
                    f.write(ip + '\n')

            batch_run_bin = os.environ.get('BATCH_RUN_INSTALL_PATH', '') + '/bin/batch_run'
            cmd = (f'{batch_run_bin} --hosts {host_list_file} '
                   f'--command "uptime -s" '
                   f'--parallel {total} --timeout 10 '
                   f'--output_message_level 3 --output_file {output_dir}/HOST')

            self.progress_signal.emit(0, total, '')

            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            while process.poll() is None:
                if self._stop_flag:
                    process.terminate()
                    process.wait()
                    self.finished_signal.emit({'ssh_failed': None, 'boot_time': {}})
                    return
                time.sleep(0.5)

                if not os.path.isdir(output_dir):
                    continue

                completed = 0
                latest_file = ''
                latest_mtime = 0

                try:
                    for fn in os.listdir(output_dir):
                        if fn == 'HOST':
                            continue

                        fp = os.path.join(output_dir, fn)

                        if os.path.getsize(fp) > 30:
                            completed += 1
                            mtime = os.path.getmtime(fp)

                            if mtime > latest_mtime:
                                latest_mtime = mtime
                                latest_file = fn
                except OSError:
                    pass

                if completed > 0:
                    self.progress_signal.emit(completed, total, latest_file)

            ssh_failed_hosts = []
            boot_time_dic = {}
            uptime_compile = re.compile(r'^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*$')

            for ip in sorted(self.host_ip_set):
                output_file = output_dir + '/' + ip

                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        content = f.read().strip()

                    output_lines = [line.strip() for line in content.split('\n') if not line.strip().startswith('>>>')]
                    output_content = '\n'.join(output_lines).strip()

                    found_uptime = False

                    for line in output_lines:
                        if uptime_compile.match(line):
                            boot_time_dic[ip] = line.strip()
                            found_uptime = True
                            break

                    if not found_uptime:
                        if not output_content:
                            reason = 'SSH无输出（连接可能被静默拒绝或密钥协商失败）'
                        else:
                            reason = MainWindow._classify_ssh_failure(output_content)
                        ssh_failed_hosts.append((ip, reason))
                else:
                    ssh_failed_hosts.append((ip, '未执行（batch_run未处理该主机）'))

            self.finished_signal.emit({'ssh_failed': ssh_failed_hosts, 'boot_time': boot_time_dic})
        except Exception:
            self.finished_signal.emit({'ssh_failed': None, 'boot_time': {}})
        finally:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)


class SecurityScanThread(QThread):
    """Worker thread for security scanning via batch_run command."""
    progress_signal = pyqtSignal(int, int, str)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, host_list, user, parallel=128, timeout=30):
        super().__init__()
        self.host_list = host_list
        self.user = user
        self.parallel = parallel
        self.timeout = timeout
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def run(self):
        total = len(self.host_list)
        results = {}

        tmp_dir = f'/tmp/batchRun/{self.user}/security_scan_{os.getpid()}'
        os.makedirs(tmp_dir, exist_ok=True)

        host_list_file = f'{tmp_dir}/host.list'
        output_dir = f'{tmp_dir}/output'
        os.makedirs(output_dir, exist_ok=True)

        with open(host_list_file, 'w') as f:
            for ip, ssh_port in self.host_list:
                if ssh_port:
                    f.write(f'{ip} ssh_port={ssh_port}\n')
                else:
                    f.write(f'{ip}\n')

        batch_run_py = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/bin/batch_run.py'

        # Inline script via base64 to avoid SCP overhead (eliminates 2 extra round-trips per host).
        script_path = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/scripts/security/security_scan.sh'

        with open(script_path, 'rb') as f:
            script_b64 = base64.b64encode(f.read()).decode()

        inline_command = f'echo {script_b64} | base64 -d | bash'

        cmd = (f'python3 {batch_run_py} --hosts {host_list_file}'
               f' --command "{inline_command}"'
               f' --parallel {self.parallel}'
               f' --timeout {self.timeout}'
               f' --output_message_level 1'
               f' --output_file {output_dir}/HOST')

        self.progress_signal.emit(0, total, 'batch_run')

        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        while process.poll() is None:
            if self._stop_flag:
                process.terminate()
                process.wait()
                break
            time.sleep(0.5)
            files = os.listdir(output_dir) if os.path.isdir(output_dir) else []
            completed = len(files)
            if completed > 0:
                latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(output_dir, f)))
                self.progress_signal.emit(completed, total, latest_file)

        for ip, _ in self.host_list:
            output_file = f'{output_dir}/{ip}'

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results[ip] = f.read()
            else:
                results[ip] = ''

        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

        self.finished_signal.emit(results)


class WebServer:
    def __init__(self):
        self.server = None
        self.server_port = None
        self.server_thread = None

    def start_server(self, target_path):
        if self.server and self.server_thread and self.server_thread.is_alive():
            return self.server_port

        from http.server import HTTPServer, SimpleHTTPRequestHandler

        port = self._find_free_port()
        web_dir = str(os.environ['BATCH_RUN_INSTALL_PATH']) + '/web'
        data_dir = str(config.db_path) + '/host_stat'

        class Handler(SimpleHTTPRequestHandler):
            def translate_path(self, path):
                path = path.split('?', 1)[0].split('#', 1)[0]

                if path.startswith('/host_stat'):
                    rel = path[len('/host_stat'):].lstrip('/')
                    return os.path.join(data_dir, rel)

                return os.path.join(web_dir, path.lstrip('/'))

            def log_message(self, format, *args):
                pass

        self.server = HTTPServer(('127.0.0.1', port), Handler)
        self.server_port = port
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        return port

    @staticmethod
    def _find_free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            return s.getsockname()[1]

    def open_url_in_firefox(self, target_path, ip_value):
        try:
            port = self.start_server(target_path)
            url = f"http://localhost:{port}?ip={ip_value}"
            webbrowser.open(url)
        except Exception as error:
            common.bprint(f'Failed to check host statistic data. Error {str(error)}', date_format='%Y-%m-%d %H:%M:%S', level='Error')


class AiInputBox(QTextEdit):
    """
    Multi-line input box for AI tab.
    Enter sends message, Shift+Enter inserts newline.
    """
    send_requested = pyqtSignal()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter) and not (event.modifiers() & Qt.ShiftModifier):
            # Don't send if input method is composing (e.g., Chinese pinyin selecting candidate).
            if not self.textCursor().block().layout().preeditAreaText():
                self.send_requested.emit()
                return

        super().keyPressEvent(event)


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
