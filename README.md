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

In victim
```sh 
tcpdump -n icmp
```

### Setting parameters
```sh 
sudo python3 ping_tool.py -c 10 -t 3 google.com yandex.ru
```
