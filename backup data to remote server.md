When using recovery mode in kali, even plug the internet, the ethernet isn't working.
```sh
ifconfig
ip link show eth0
ip link set eth0 up
```
