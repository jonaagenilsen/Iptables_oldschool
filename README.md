# Iptables_oldschool
bash script (/etc/rc.local) for basic firewalling

```
#!/bin/bash
#

echo 1 > /proc/sys/net/ipv4/tcp_syncookies        # TCP SYN COOKIE PROTECTION FROM SYN FLOODS
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter    # ENABLE SOURCE ADDRESS SPOOFING PROTECTION
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians # LOG PACKETS WITH IMPOSSIBLE ADDRESSES (DUE TO WRONG ROUTES) ON YOUR NETWORK
echo 0 > /proc/sys/net/ipv4/ip_forward            # DISABLE IPV4 FORWARDING

ext_eth_isp="eno1"
ip=1.1.1.1
ssh_port=9099
ssh_allow_1=2.2.2.2

iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P OUTPUT ACCEPT

# Flush all rules, erase non-default chains
iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT

# Allow icmp
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Custom chain with default policy = DROP.
iptables -N dropInputDefaultTCP
iptables -A dropInputDefaultTCP -m limit --limit 15/minute -j LOG --log-level 4 --log-prefix 'DROP: TCP Input '
iptables -A dropInputDefaultTCP -j DROP

iptables -N dropInputDefaultUDP
iptables -A dropInputDefaultUDP -m limit --limit 15/minute -j LOG --log-level 4 --log-prefix 'DROP: UDP Input '
iptables -A dropInputDefaultUDP -j DROP

iptables -N dropInputInvalid
iptables -A dropInputInvalid -m limit --limit 15/minute -j LOG --log-level 4 --log-prefix 'DROP: InputInvalid '
iptables -A dropInputInvalid -j DROP

iptables -N dropOutputInvalid
iptables -A dropOutputInvalid -m limit --limit 15/minute -j LOG --log-level 4 --log-prefix 'DROP: OutputInvalid '
iptables -A dropOutputInvalid -j DROP

# Buggers
# iptables -A INPUT -s 70.231.56.209 -j DROP

# Bad packets
iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN  -j dropInputInvalid # Invalid syn packets
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN      -j dropInputInvalid # Invalid syn packets
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST      -j dropInputInvalid # Invalid syn packets
iptables -A INPUT -p tcp ! --syn -m state --state NEW     -j dropInputInvalid # Make sure NEW incoming packets are SYN packets. Else DROP them
iptables -A INPUT -p tcp --tcp-flags ALL ALL              -j dropInputInvalid # Malformed xmas packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE             -j dropInputInvalid # Malformed null packets
iptables -A INPUT -m state --state INVALID                -j dropInputInvalid # Invalid packets
iptables -A INPUT -f                                      -j dropInputInvalid # Fragmented packets

# Bad packets
iptables -A OUTPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j dropOutputInvalid # Invalid syn packets
iptables -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN     -j dropOutputInvalid # Invalid syn packets
iptables -A OUTPUT -p tcp --tcp-flags SYN,RST SYN,RST     -j dropOutputInvalid # Invalid syn packets
iptables -A OUTPUT -p tcp ! --syn -m state --state NEW    -j dropOutputInvalid # Make sure NEW incoming packets are SYN packets. Else DROP them
iptables -A OUTPUT -p tcp --tcp-flags ALL ALL             -j dropOutputInvalid # Malformed xmas packets
iptables -A OUTPUT -p tcp --tcp-flags ALL NONE            -j dropOutputInvalid # Malformed null packets
iptables -A OUTPUT -m state --state INVALID               -j dropOutputInvalid # Invalid packets
iptables -A OUTPUT -f                                     -j dropOutputInvalid # Fragmented packets

iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT # Established & related TCP
iptables -A INPUT -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT # Established & related UDP

# Allow new connections. SSH.
iptables -A INPUT -i $ext_eth_isp -s $ssh_allow_1  -p tcp --dport $ssh_port -m state --state NEW -j ACCEPT

# Drop & log everything not allowed above.
iptables -A INPUT -p tcp -j dropInputDefaultTCP
iptables -A INPUT -p udp -j dropInputDefaultUDP
#iptables -A INPUT -p tcp -j DROP
#iptables -A INPUT -p udp -j DROP

touch /var/lock/subsys/local

exit 0
```
