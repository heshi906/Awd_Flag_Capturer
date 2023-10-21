import json
import datetime
from pwn import *


def search_robot(i):
    time_data1 = datetime.datetime.now().strftime("%y_%m_%d_%H_%M")
    try:
        for j in range(cishu):
            port = start_port + j * pinglv + i
            p = remote(server, port, timeout=timeout)
            rec = p.recvline(timeout=timeout)
            ports[port] = rec.decode()
            with open("ports" + time_data1 + ".txt", 'a+') as f:
                f.write("ports:" + str(port) + '\n')
                f.close()
    except:
        pass


def searcher():
    threads = []
    for i in range(0, pinglv):
        thread = threading.Thread(target=search_robot, args=(i,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

    with open("ports.json", "w+") as f:
        json.dump(ports, f)
        f.close()


ports = {}
pinglv = 1000  # 这里是频率，可以自定义
start_port = 13000  # 起始端口号
end_port = 20000  # 终止端口号
timeout = 5  # 最长等待时间
server = "ctf.qwq.cc"  # 服务器号或者域名
cishu = (end_port - start_port) // pinglv
