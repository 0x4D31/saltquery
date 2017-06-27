# sqhunter
Threat hunter based on osquery, Salt Open and Cymon API

## Description
You need to run _sqhunter_ on your salt-master server.

## Features
* Query open network sockets and check them against threat intelligence sources

## Requirements
* [Salt Open](https://saltstack.com/salt-open-source/) (salt-master, salt-minion)¹
* Python 2.7
* salt _(you may need to install gcc, gcc-c++, python dev)_

## Usage
#### open_sockets
```
[root@localhost ~]# python sqhunter.py -oS -t '*'

               __                __           
   _________ _/ /_  __  ______  / /____  _____
  / ___/ __ `/ __ \/ / / / __ \/ __/ _ \/ ___/
 (__  ) /_/ / / / / /_/ / / / / /_/  __/ /    
/____/\__, /_/ /_/\__,_/_/ /_/\__/\___/_/     
        /_/                                   
 threat hunter based on osquery and salt open  
==============================================


[+] Alert - Host: 10.10.10.55

    + Process and network socket info:
        - pid: 15003
        - name: telnet
        - cmdline: telnet 98.131.172.1 80
        - local_address: 10.10.10.55
        - local_port: 47722
        - remote_address: 98.131.172.1
        - remote_port: 80
        - protocol: 6

    + Threat reports:
        - title: Malware activity reported by IBM X-Force Exchange
          date: 2015-09-21T09:04:10Z
          details_url: https://exchange.xforce.ibmcloud.com/ip/98.131.172.1
          tag: malware
        - title: Malware reported by cleanmx-malware
          date: 2015-02-24T15:26:00Z
          details_url: http://www.virustotal.com/latest-report.html?resource=5bc647742434f743114d3397b2cf74b0
          tag: malware
        - title: Malicious activity reported by urlquery.net
          date: 2015-02-23T21:39:53Z
          details_url: http://urlquery.net/report.php?id=1424725884093
          tag: malicious activity

[+] Alert - Host: 10.10.10.56

    + Process and network socket info:
        - pid: 14448
        - name: telnet
        - cmdline: telnet 103.31.186.29 80
        - local_address: 10.10.10.56
        - local_port: 59115
        - remote_address: 103.31.186.29
        - remote_port: 80
        - protocol: 6

    + Threat reports:
        - title: Malicious activity reported by urlquery.net
          date: 2017-03-31T10:56:25Z
          details_url: http://urlquery.net/report.php?id=1490956880695
          tag: malicious activity
```
#### custom query
```
[root@localhost ~]# python sqhunter.py -q "select * from last where username = 'root' and time > ((select unix_time from time) - 3600);" -p 10.10.10.55

               __                __           
   _________ _/ /_  __  ______  / /____  _____
  / ___/ __ `/ __ \/ / / / __ \/ __/ _ \/ ___/
 (__  ) /_/ / / / / /_/ / / / / /_/  __/ /    
/____/\__, /_/ /_/\__,_/_/ /_/\__/\___/_/     
        /_/                                   
 threat hunter based on osquery and salt open  
==============================================

{
    "10.10.10.55": {
        "data": [
            {
                "host": "10.10.3.6", 
                "pid": "15889", 
                "time": "1498591524", 
                "tty": "pts/0", 
                "type": "7", 
                "username": "root"
            }
        ], 
        "result": true
    }
}
```
#### queries from the default query packs
```
[root@localhost ~]# python sqhunter.py -qP crontab -p 10.10.10.55

               __                __           
   _________ _/ /_  __  ______  / /____  _____
  / ___/ __ `/ __ \/ / / / __ \/ __/ _ \/ ___/
 (__  ) /_/ / / / / /_/ / / / / /_/  __/ /    
/____/\__, /_/ /_/\__,_/_/ /_/\__/\___/_/     
        /_/                                   
 threat hunter based on osquery and salt open  
==============================================

{
    "10.10.10.55": {
        "data": [
            {
                "command": "root run-parts /etc/cron.hourly", 
                "day_of_month": "*", 
                "day_of_week": "*", 
                "event": "", 
                "hour": "*", 
                "minute": "01", 
                "month": "*", 
                "path": "/etc/cron.d/0hourly"
            }
        ], 
        "result": true
    }
}
```

## TODO:
* Slack integration
* More features to add..
