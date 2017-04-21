# VPN

The password for all certs will be '1234' (without quote mark)


If the certificate expires, you may want to generate your own with 'gen_certs.sh'.

Steps to run the program :
1) Generate CA certificates. Place the CA cert on client machine too.
2) Generate the certificates on client side and server side.
2) Run the vpn executable as :
sudo ./vpn -s "portno" -d on Server side
sudo ./vpn -c "serverdomain.com":"portno" -d on Client side
3)Authenticate the client with username and password as seed and dees.
4) Run 

 NETWORK MAP

HOST A: 10.0.4.6 GATEWAY 10.0.4.1
HOST B: 10.0.5.7 GATEWAY 10.0.5.6
GATEWAY A (VPN Client):
  LAN: 10.0.4.1/24
  INTER-CONN: 192.168.56.102  (connected with GATEWAY A)
  NAT: DHCP / for the Internet Access

GATEWAY B (VPN Server):
  LAN: 10.0.5.6
  INTER-CONN: 192.168.56.103  (connected with GATEWAY B)
  NAT: DHCP / for the Internet Access
