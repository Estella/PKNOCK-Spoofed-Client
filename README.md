# PKNOCK-Spoofed-Client (IPv4)
Spoofed Client for pknock module from xtables-addons for iptables
```
$IP4FW -A INPUT -p udp -m udp --dport 47000 -m pknock --knockports 47000 --name KNOCKLIST --opensecret MYSTAGIC --closesecret DOGBONE --autoclose 240 -j DROP
$IP4FW -A INPUT -p tcp -m tcp --syn --dport 22 -m pknock --checkip --name KNOCKLIST -m state --state NEW -j ACCEPT
$IP4FW -A INPUT -p udp -m udp --dport 1900 -m pknock --checkip --name KNOCKLIST -m state --state NEW -j ACCEPT
```
```
[root@nat-fw(~/spoof)]> ./knock 10.47.47.105 10.47.47.107 47000 MYSTAGIC
 Spoofing Source IP: 10.47.47.105
 Knock Server IP: 10.47.47.107 port: 47000
 Knock token: afd184cddc7372740912587e0d38be42f60298f2600a3759b6017755ad932c6b
 Knock sent.
```

pknock module: https://github.com/tinti/xtables-addons/tree/master/extensions/pknock

Other port knocking has some more flexibility is fwknop and knockknock both have single packet authorization which I prefer over just port sequences.

https://www.cipherdyne.org/fwknop/
https://moxie.org/software/knockknock/

Another one is knockd which is designed to use port sequences, becareful if an advasary can intercept your traffic they can learn the sequence of ports to trigger whitelist.
Is safer to remain in the realm of some form of cryptographic solution. Moxie has a good write up about it on the knockknock page expressing concerns for various methods/solutions.

I did like that this pknock is already apart of xtables-addons which makes it easy to deploy, but has some issues if your behind a NAT network,
I often am on wireless networks with my laptop and phone and often need to gain access, however the pknock doesn't have options to specify the host,
since it's using the source address as part of the check which if your behind a router on a NAT ip your address will differ and fail to auth. 
This client can resolve that, since it can spoof any address, however not many networks have spoofing. 
So I spoof over the VPN subnet and can get a WAN side address whitelisted for access.

fwknop has a nice android client that makes portknocking on the go a lot easier - https://github.com/jp-bennett/Fwknop2/releases
