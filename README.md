# Awd_Flag_Capturer
这是一个awd中pwn方向的flag抓取器。设定扫描范围，复制入写好的exp，就可以解放双手，自动获取flag，并且放到一个txt文件中。

## 使用方法

```
1.在exps.py中复制入自己的exp，格式参考我的示例
2.在fastsearcher.py中根据注释修改参数
3.修改catflags.py中的进入exp的条件
4.注意exp所需文件是否具备
5.运行catflags.py
```

## 提示

```
在虚拟机中跑会导致扫描速度极慢，建议在本机跑。
若在本机中pwntools功能异常。在本机扫描，到虚拟机运行[2]抓取flag
```

