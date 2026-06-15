---
name: batchrun_usage
description: batchRun工具自身的安装、配置、使用说明，包括batch_run CLI批量执行、GUI功能、主机管理、数据采集等全部功能
version: 1.0.0
tags:
  - batchrun
  - batch_run
  - 批量执行
  - 批量操作
  - 批量运行
  - 远程执行
  - 远程命令
  - 并行执行
  - 并行操作
  - ssh批量
  - 主机列表
  - 主机分组
  - host.list
  - 分组
  - 采集
  - sample
  - 网络扫描
  - network_scan
  - 资产
  - asset
  - 密码
  - save_password
  - 怎么用batch
  - 如何batch
  - 主机清单
  - 安装部署
  - 配置文件
  - ai
  - AI助手
  - 集群分析
  - cluster_analysis
  - 安全分析
  - security_analysis
  - 安全扫描
  - 安全审计
---

# batchRun 工具使用手册

## 一、项目简介

batchRun 是一款 HPC 系统批量操作、资产管理和信息采集工具，支持命令行和 GUI 两种模式。核心能力：
- **批量执行**：通过 SSH 在大量远程主机上并行执行命令
- **资产管理**：管理主机清单、分组、硬件信息
- **数据采集**：定期采集主机状态、网络拓扑、队列信息
- **安全分析**：集群安全审计和风险评估

---

## 二、CLI 批量执行（batch_run）

### 2.1 命令格式

```bash
batch_run [选项]
```

### 2.2 参数说明

| 参数 | 说明 | 示例 |
|------|------|------|
| `-H, --hosts` | 指定目标主机（IP/主机名/文件） | `-H 10.151.1.1 10.151.1.2` |
| `-G, --groups` | 指定主机分组 | `-G GPU_SERVER ALL` |
| `-L, --list` | 仅列出匹配的主机，不执行命令 | `-G ALL -L` |
| `-u, --user` | 指定 SSH 登录用户（默认当前用户） | `-u root` |
| `-p, --password` | 指定 SSH 密码（不推荐明文） | |
| `-c, --command` | 要执行的命令 | `-c 'uptime'` |
| `-P, --parallel` | 并行度：0=全部并行，1=串行，n=n路并行 | `-P 128` |
| `-t, --timeout` | SSH 超时秒数（串行默认10s，并行默认20s） | `-t 30` |
| `-l, --output_message_level` | 输出级别（0-4） | `-l 1` |
| `-o, --output_file` | 输出到文件（HOST会被替换为主机IP） | `-o /tmp/out/HOST` |
| `-g, --gui` | 启动 GUI 模式 | |

### 2.3 主机指定方式

```bash
# 直接指定 IP
batch_run -H 10.151.1.1 10.151.1.2 -c 'uptime'

# 指定 IP:端口
batch_run -H 10.151.1.1:2222 -c 'uptime'

# 排除某主机（波浪线前缀）
batch_run -H ALL ~10.151.1.1 -c 'uptime'

# 从文件读取主机列表
batch_run -H /path/to/host_file -c 'uptime'

# 指定分组
batch_run -G GPU_SERVER -c 'nvidia-smi'

# ALL 表示全部主机/分组
batch_run -H ALL -c 'hostname'
batch_run -G ALL -c 'hostname'

# 排除分组
batch_run -G ALL ~TEST_GROUP -c 'uptime'
```

### 2.4 输出级别

| 级别 | 含义 |
|------|------|
| 0 | 仅打印主机信息（IP） |
| 1 | 仅打印命令输出 |
| 2 | 打印主机信息 + 命令输出首行 |
| 3 | 打印主机信息 + 完整命令输出（默认） |
| 4 | 详细模式，含 SSH 命令本身 |

### 2.5 输出到文件

使用 `-o` 将每台主机的输出分别保存到文件：

```bash
# HOST 会被替换为实际的主机 IP
batch_run -G ALL -P 128 -c 'df -h' -o /tmp/disk_check/HOST

# 执行后每台主机有独立输出文件：
# /tmp/disk_check/10.151.1.1
# /tmp/disk_check/10.151.1.2
# ...
```

### 2.6 常用场景

```bash
# 检查所有主机负载
batch_run -G ALL -P 128 -c 'uptime'

# 检查磁盘使用
batch_run -G ALL -P 128 -c 'df -h /tmp'

# 查看内存状态
batch_run -G ALL -P 128 -c 'free -h'

# 检查指定进程
batch_run -G ALL -P 128 -c 'ps aux | grep java | grep -v grep'

# 查看系统版本
batch_run -G ALL -P 128 -c 'cat /etc/os-release'

# 批量重启服务（危险操作！）
batch_run -G WEB_SERVER -P 10 -c 'systemctl restart nginx'

# 批量分发文件（结合 scp）
batch_run -G ALL -P 128 -c 'scp user@mgmt:/path/file /local/path/'

# 列出某分组的所有主机
batch_run -G GPU_SERVER -L
```

---

## 三、主机列表（host.list）

### 3.1 格式

INI 风格，`[group]` 定义分组，每行一个主机：

```ini
[GPU_SERVER]
10.151.1.1 host_name=gpu01 ssh_port=22
10.151.1.2 host_name=gpu02

[WEB_SERVER]
10.151.2.1 host_name=web01
10.151.2.2 host_name=web02

[ALL]
# 支持引用其他分组
sub_groups = GPU_SERVER WEB_SERVER
```

### 3.2 特殊语法

- `host_name=xxx`：指定主机名
- `ssh_port=xxx`：指定 SSH 端口（非22时必填）
- `sub_groups = G1 G2`：包含子分组
- `exclude_hosts = ip1 ip2`：排除主机
- `exclude_groups = G1`：排除子分组
- 支持通配符 `*` 匹配分组名

---

## 四、GUI 模式（batch_run_gui）

### 4.1 启动

```bash
batch_run_gui
# 或
batch_run -g
```

### 4.2 标签页

| 标签页 | 功能 |
|--------|------|
| NETWORK | 网络拓扑：zone/network/IP 树 + 矢量拓扑图 |
| ASSET | 资产管理：设备信息表格 |
| HOST | 主机管理：分组树 + 多维筛选 + 详情表格 |
| STAT | 状态趋势：host_stat 历史曲线（负载/CPU/内存/swap/tmp） |
| RUN | 批量执行：选择主机 + 输入命令 + 实时输出 |
| LOG | 命令历史：查看历史执行记录 |

### 4.3 菜单功能

| 菜单 | 功能 |
|------|------|
| File | 导出表格、退出 |
| Setup | 选择数据源目录 |
| Tool | 更新 host.list、网络扫描、采集主机信息/状态/队列 |
| AI | AI 助手对话、集群分析报告、安全分析报告 |

---

## 五、数据采集工具

### 5.1 网络扫描（network_scan）

扫描 IP 网段，发现活跃主机：

```bash
# 扫描所有配置的网段
network_scan --alive

# 结果保存到 db/network_scan/network_scan.json
```

### 5.2 主机信息采集（sample_host_info）

采集 OS、CPU、内存等静态信息：

```bash
sample_host_info --groups ALL
# 结果保存到 db/host_info/host_info.json
```

### 5.3 主机状态采集（sample_host_stat）

采集运行时状态（负载、CPU利用率、内存、swap、tmp）：

```bash
sample_host_stat --groups ALL
# 结果保存到 db/host_stat/YYYYMMDD/HHMMSS/host_stat.json
```

### 5.4 队列信息采集（sample_host_queue）

采集 LSF/openlava 调度器队列映射：

```bash
sample_host_queue --groups ALL
# 结果保存到 db/host_queue/host_queue.json
```

---

## 六、密码管理

### 6.1 保存密码

```bash
save_password
# 交互式输入密码，加密保存到 db/password/<user>
```

密码保存后，`batch_run` 和 GUI 可免密执行 SSH（自动读取加密密码）。

### 6.2 切换用户

```bash
batch_run -u other_user -c 'whoami'
```

---

## 七、安装与配置

### 7.1 安装

```bash
python3 install.py
```

安装脚本会：
1. 检查 Python 版本（要求 3.12+）
2. 生成 shell 包装脚本（bin/batch_run, bin/batch_run_gui, tools/*）
3. 生成默认配置文件 config/config.py

### 7.2 配置文件（config/config.py）

| 变量 | 说明 |
|------|------|
| `host_list` | 主机清单文件路径 |
| `db_path` | 数据库根目录 |
| `default_ssh_command` | SSH 命令模板 |
| `serial_timeout` | 串行模式超时（秒） |
| `parallel_timeout` | 并行模式超时（秒） |
| `fuzzy_match` | 是否支持主机名模糊匹配 |
| `illegal_command_list` | 禁止执行的命令列表 |
| `ai_api_base_url` | AI API 地址 |
| `ai_api_key` | AI API 密钥 |
| `ai_model_name` | AI 模型名称 |
| `ai_dangerous_commands` | AI 执行前需确认的危险命令列表 |

---

## 八、AI 助手中使用 batch_run

在 AI 对话中，你可以通过 `run_command` 工具调用 `batch_run` 命令来批量操作远程主机。

### 8.1 重要规则

1. **batch_run 的完整路径**：`$BATCH_RUN_INSTALL_PATH/bin/batch_run`
2. **并行执行**：对多台主机操作务必加 `-P 128`（或更大），否则串行执行非常慢
3. **超时设置**：远程命令执行时间长时需加 `-t 30` 或更大值
4. **输出级别**：如果只需要结果数据，使用 `-l 1`（仅命令输出）便于解析
5. **输出到文件**：大量主机时用 `-o /tmp/result/HOST` 收集结果，再逐一读取分析

### 8.2 典型调用模式

```bash
# 查看所有主机负载（实时）
$BATCH_RUN_INSTALL_PATH/bin/batch_run -G ALL -P 128 -t 20 -l 3 -c 'uptime'

# 检查磁盘空间不足的主机
$BATCH_RUN_INSTALL_PATH/bin/batch_run -G ALL -P 128 -t 20 -l 1 -c 'df -h / /tmp | tail -n +2'

# 查找特定进程
$BATCH_RUN_INSTALL_PATH/bin/batch_run -G ALL -P 128 -t 20 -l 3 -c 'ps aux | grep -v grep | grep java'

# 检查服务状态
$BATCH_RUN_INSTALL_PATH/bin/batch_run -G WEB_SERVER -P 128 -t 20 -l 3 -c 'systemctl is-active nginx'

# 输出到文件后分析
$BATCH_RUN_INSTALL_PATH/bin/batch_run -G ALL -P 128 -t 30 -l 1 -c 'cat /etc/os-release' -o /tmp/os_info/HOST
# 然后读取 /tmp/os_info/ 下各文件进行分析

# 列出指定分组的主机
$BATCH_RUN_INSTALL_PATH/bin/batch_run -G GPU_SERVER -L
```

### 8.3 注意事项

- 命令中包含单引号时需要转义或用双引号包裹
- 命令中包含管道符 `|` 时需要用引号将整个命令括起来
- `batch_run` 会自动使用已保存的加密密码进行 SSH 认证
- 如果某台主机 SSH 超时或失败，不影响其他主机的执行
- 使用 `-o` 输出文件时，HOST 占位符会被替换为主机 IP

---

## 九、常见问题

### Q: batch_run 连接超时？
- 检查目标主机是否可达（ping）
- 检查 SSH 端口是否正确（host.list 中 ssh_port 配置）
- 增大 `-t` 超时值
- 确认密码已保存（`save_password`）

### Q: 如何查看有哪些分组？
- GUI 的 HOST 标签页左侧树形列表
- 或直接查看 host.list 文件中的 `[group]` 段

### Q: 如何添加新主机？
- 编辑 host.list 文件，在对应分组下添加行
- 或使用 `switch_etc_hosts` 工具从 /etc/hosts 自动转换

### Q: 并行数设多少合适？
- 一般 128 即可覆盖大部分场景
- 设为 0 表示全部并行（主机多时可能超出系统 fd 限制）
- 串行（默认 -P 1）适合需要逐一确认的场景

### Q: 输出太多看不过来？
- 使用 `-l 2` 只看每台主机的首行输出
- 使用 `-o` 导出到文件后用 grep 筛选
- 在命令中加 `| grep xxx` 过滤
