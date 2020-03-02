# Name
why L1br4 ? because it's the my first time to find vul and use the vul to get root(not just know the vul and write exp), so i decided to use my constellation to name it

# Analyse
you can see the analyse from my [blog](http://nirvan.360.cn/blog/?p=1053)

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
