route delete default gw 10.0.5.1 eth15
route add default gw 192.168.56.1 eth14
ip addr add 10.0.6.0/24 dev tun0
ifconfig tun0 up
route add -net 10.0.7.0 netmask 255.255.255.0 dev tun0
route add -net 10.0.4.0/24 dev tun0
sysctl net.ipv4.ip_forward=1
ifconfig
route -n
