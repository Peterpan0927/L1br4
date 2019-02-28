# Name
why L1br4 ? because it's the my first time to find vul and use the vul to get root(not just know the vul and write exp), so i decided to use my constellation to name it

# Analyse
you can see the analyse from my [blog](https://peterpan980927.cn/2019/02/26/Nday%E6%BC%8F%E6%B4%9E%E4%BB%8E%E6%8C%96%E6%8E%98%E5%88%B0%E5%88%A9%E7%94%A8/#more)

# target
on MacOS 10.13 or 10.13.1

# Vul

1. `queryCompletion`in`AVEBridge`
2. `getDisplayPipeCapability`in`AppleIntelFramebufferAzul`
3. `ReadRegister32`in`AppleIntelFramebufferAzul`

# How to use

```shell
make
```
At last, use the command:
```
./pwn
```
And you will get root~
Having fun with this

![exp](https://pbs.twimg.com/media/D0UvZJJUUAAP-I5.jpg)
