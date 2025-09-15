### Regular ping of several hosts
```sh 
sudo python3 ping_tool.py google.com yandex.ru 8.8.8.8
```

### With traceroute
```sh 
sudo python3 ping_tool.py --traceroute google.com'
```

### Smurf attack
```sh 
sudo docker-compose up -d --build
```
```sh 
sudo docker exec -it icmptoolkit-attacker-1 bash
```
```sh 
sudo docker exec -it icmptoolkit-victim-1 bash
```

In attacker
```sh 
python ping_tool.py responder --smurf --target 172.28.0.20
```
```sh 
python3 ping_tool.py --smurf --high-intensity --target 172.28.0.20 --duration 60 --target-mbps 75 172.28.255.255
```

In victim
```sh 
tcpdump -n icmp
```
For test the load on the network card during an intensity smurf-attack
```sh
iftop -i eth0
```

### Setting parameters
```sh 
sudo python3 ping_tool.py -c 10 -t 3 google.com yandex.ru
```
