#!/bin/bash

echo "===SSHD_CONFIG==="
cat /etc/ssh/sshd_config 2>/dev/null || echo "PERMISSION_DENIED"

echo "===PASSWD_AUDIT==="
awk -F: 'BEGIN{OFS=":"}{print $1,$3,$7}' /etc/passwd 2>/dev/null

echo "===FAILED_LOGINS==="
timeout 10 lastb 2>/dev/null | wc -l
timeout 15 journalctl -u sshd --since "7 days ago" --no-pager -q 2>/dev/null | grep -c "Failed password" || echo 0

echo "===LISTENING_PORTS==="
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "PERMISSION_DENIED"

echo "===SUID_SGID==="
timeout 20 find /tmp /var/tmp /dev/shm /home /opt /usr/local -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null

echo "===WORLD_WRITABLE==="
find /tmp /var/tmp /dev/shm -maxdepth 0 -perm -1002 2>/dev/null
ls -ld /tmp /var/tmp 2>/dev/null

echo "===CRONTAB==="
for f in /var/spool/cron/*; do
    [ -f "$f" ] || continue
    user=$(basename "$f")
    while IFS= read -r line; do
        case "$line" in ''|\ *|\#*) continue;; esac
        echo "USER_CRON|${user}|${line}"
    done < "$f"
done

echo "===FIREWALL==="
echo "SKIPPED"

echo "===KERNEL_SECURITY==="
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
echo "aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"

echo "===SENSITIVE_FILES==="
stat -c "%a %U %G %n" /etc/shadow /etc/gshadow /etc/passwd /root/.ssh/authorized_keys 2>/dev/null || echo "PERMISSION_DENIED"

echo "===LAST_LOGINS==="
timeout 10 last -n 20 2>/dev/null | head -20

echo "===SECURITY_TOOLS==="
which sestatus apparmor_status fail2ban-client 2>/dev/null
type setenforce 2>/dev/null

echo "===ZOMBIE_PROCS==="
ps aux 2>/dev/null | grep -c "[Zz]ombie\|defunct" || echo 0

echo "===BOOT_TIME==="
uptime -s 2>/dev/null || who -b 2>/dev/null

echo "===END==="
