### Regular ping of several hosts
sudo python3 ping_tool.py google.com yandex.ru 8.8.8.8

### With traceroute
```sh 
sudo python3 ping_tool.py --traceroute google.com'
```

### Smurf attack
```sh 
sudo python3 ping_tool.py --smurf --target 192.168.1.100 192.168.1.255
```

### Setting parameters
```sh 
sudo python3 ping_tool.py -c 10 -t 3 google.com yandex.ru
```
