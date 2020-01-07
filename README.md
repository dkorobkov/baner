# baner
A primitive app written in C to scan SSH logs and ban intruders

v.0.1 from Jan 7, 2020

Was inspired by fail2ban, but python does not work on my box. Also suitable for 
embedded devices. Very small, does not produce much load on system.

The app bans forever (or until exit) up to 10000 intruders detected by SSH it its 
/var/log/secure or /var/log/auth.log. Log format must be like this:

Jan  7 03:58:00 vps sshd[3018]: Failed password for invalid user ebs from 31.222.195.30 port 51327 ssh2

Baner polls log file once a second, reading its tail line by line. It is triggered by 
"Failed password". It extracts intruder's IP from the line 
and stores internally. If this IP is found more than 3 times (regardless of time 
interval between them), command to iptables is issued that will drop incoming 
packets from this IP. 

Baner must be run as root to be able to send commands to iptables.

If terminated by SIGHUP (kill -HUP `pidof baner`) baner will unblock all previously
blocked IPs. If terminated by SIGKILL these IPs will stay locked until reboot.

So far baner is very primitive: no fork, no logging, nothing. Will probably improve 
it in future.


BUILD:
gcc -o baner baner.c

INSTALL:
Add into your /etc/rc.local:
/path/to/baner >/dev/null &

TEST:
Run /path/to/baner from console and watch what happens.


Do what the fuck you want to with this code  (WTFPL license).
