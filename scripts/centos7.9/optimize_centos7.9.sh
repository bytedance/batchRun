#!/bin/bash

#stop firewall
systemctl stop firewalld.service
systemctl disable firewalld.service

# Disable selinux
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config

# Other setting
systemctl stop nscd
systemctl disable nscd
systemctl disable dnssec-trigger
systemctl disable telnet.socket
systemctl disable rlogin.socket
systemctl disable rexec.socket
systemctl enable autofs
systemctl disable rsh.socket
systemctl set-default multi-user.target

# Set from powersave mode to max performance
tuned-adm profile latency-performance
x86_energy_perf_policy -v performance
cpupower frequency-set --governor performance
cpupower idle-set -D 0
