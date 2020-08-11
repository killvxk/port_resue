# 端口复用
## 技术原理
+ 注入SSH/Apache2等进程，挂钩accept/read/write等函数。复用对方服务端口，加密转发自身流量，实现反弹Shell、文件上传下载等。
## 使用方法

+ client_on_windows
  + define HOST 处设定目标IP
  + define PORT 处设定目标端口
  + 使用VS2019编译运行
+ server_on_linux
  + injectme.c => define PASSWORD处设定密码（默认为Qihoo）
  + 运行对应inject-xxx脚本（可能需要设定chmod +x inject-xxx.sh）

## 测试概况

| 操作系统  | SSH:22                                         | apache2:80                                       |
| --------- | ---------------------------------------------- | ------------------------------------------------ |
| kali 2020 | 一切正常                                       | 一切正常                                         |
| ubuntu 9  | 一切正常                                       | 注入worker进程段错误（即使注入空so文件）         |
| centos 7  | 成功注入，运行过程段错误(需要事先setenforce 0) | 注入worker进程dlopen调用失败（即使注入空so文件） |
