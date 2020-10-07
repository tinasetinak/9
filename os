#!/bin/bash
echo -e "\e[40;38;5;226m " 
echo " WELCOME TO AUTOSCRIPT VpsProject "
echo "################################################################################" 
echo "#                                                                              #" 
echo "#      SSSSSSSSSSSSSSSSS  sssssssssssssssss  HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSS             SSSSSS             HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSS             SSSSSS             HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHHHHHHHHHHHHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHHHHHHHHHHHHHHHHHHH        #" 
echo "#                 SSSSSS             SSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#                 SSSSSS             SSSSSS  HHHHHHHHH        HHHHHHHHH        #"
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#------------------------------------------------------------------------------#" 
echo "#          SELAMAT DATANG DI SCRIPT AUTO SETUP VPS BY VPSPROJECT.              #" 
echo "#                       SCRIPT VERSION V2.0 FOR DEBIAN 7-8-9                   #"
echo "#                               SEMOGA BERMANFAAT                              #" 
echo "#------------------------------------------------------------------------------#" 
echo "################################################################################"
echo "========================================"
echo "CLICK 'I' SETUP VPS Non-Local"
echo "CLICK 'L' SETUP VPS Local" 
echo "========================================"
read -p "Location : " -e loc
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
if [ $USER != 'root' ]; then
echo "ต้องใช้รูทนะ"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "ควยเอ้ย รูท"
exit 2
fi
if [[ ! -e /dev/net/tun ]]; then
echo "TUN ไม่ตอบสนอง"
exit 3
fi
echo "ทำใช้เอง"
clear
echo "ตั้งเวลา กรุงเทพ  +7"
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime;
clear
echo "เปิด IPV4 กับ IPV6"
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear
echo "แพค สแปม"
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove postfix*;
apt-get -y --purge remove bind*;
clear

sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt-get update;
apt-get -y autoremove;
apt-get -y install wget curl;
echo "
"
# detail
country=MY
state=Terengganu
locality=-
organization=Interpass
organizationalunit=InterpassGroup
commonname=Hake
email=-
cd

# script
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/tinasetina/9/master/common-password"
chmod +x /etc/pam.d/common-password
# Install Dos Deflate
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/tinasetina/9/master/ddos-deflate-master.zip
unzip master.zip
cd ddos-deflate-master
./install.sh
cd
service exim4 stop;sysv-rc-conf exim4 off;
# webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart
# dropbear
apt-get -y install dropbear
wget -O /etc/default/dropbear "https://raw.githubusercontent.com/tinasetina/9/master/dropbear"
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="\/etc\/issue.net"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
# install banner
cd
wget -O /etc/issue.net "https://raw.githubusercontent.com/tinasetina/9/master/banner.txt"
chmod +x /usr/bin/banner.txt
service dropbear restart
# squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/tinasetina/9/master/squid.conf"
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/tinasetina/9/master/squid.conf"
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf
sed -i "s/ipserver/$myip/g" /etc/squid/squid.conf
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf

# deny ads
cat > /etc/squid/ads.txt <<-END
images.digi.my
101order.com
music.digi my
180hits.de
180searchassistant.com
207.net
247media.com
24log.com
24log.de
24pm-affiliation.com
2mdn.net
2o7.net
360yield.com
4affiliate.net
4d5.net
50websads.com
518ad.com
51yes.com
600z.com
777partner.com
77tracking.com
7bpeople.com
7search.com
99count.com
a-ads.com
a-counter.kiev.ua
a.0day.kiev.ua
a.aproductmsg.com
a.collective-media.net
a.consumer.net
a.mktw.net
a.sakh.com
a.ucoz.net
m.whatsapp.net
m.wechat.com
music.qq.com
play.spotify.com
api.joox.com
era.fm
play.kkbox.com
raku.my
play.iflix.com
netflix.com
tidal.my
tidal.com
playstore.com
static.facebook.com
m.kkbox.com
a.ucoz.ru
a.xanga.com
a32.g.a.yimg.com
aaddzz.com
www.volleyball-doppeldorf.de
www.vvvic.com
www.whitesports.co.kr
www.widestep.com
www.wigglewoo.com
xoomer.alice.it
xorgwebs.webs.com
zibup.csheaven.com
zjjlf.croukwexdbyerr.net
zkic.com
zous.szm.sk
zt.tim-taxi.com
zyrdu.cruisingsmallship.com
END


# openvpn
apt-get -y install openvpn
cd /etc/openvpn/
wget -O openvpn.tar "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/openvpn.tar"
tar xf openvpn.tar;rm openvpn.tar
#curl -O https://raw.githubusercontent.com/Angristan/openvpn-install/master/openvpn-install.sh
#chmod +x openvpn-install.sh
#./openvpn-install.sh
wget -O /etc/rc.local "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/rc.local"
chmod +x /etc/rc.local

# nginx
apt-get -y install nginx php-fpm php-mcrypt php-cli libexpat1-dev libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/php/7.0/fpm/pool.d/www.conf "https://raw.githubusercontent.com/tinasetina/9/master/www.conf"
mkdir -p /home/vps/public_html
echo "<pre>Budak Sabah</pre>" > /home/vps/public_html/index.php
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/tinasetina/9/master/vps.conf"
sed -i 's/listen = \/var\/run\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
# etc
#cp /root/client.ovpn /home/vps/public_html
#wget -O /home/vps/public_html/client.ovpn /root/client.ovpn
wget -O /home/vps/public_html/client.ovpn "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/client.ovpn"
wget -O /home/vps/public_html/client1.ovpn "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/client1.ovpn"
wget -O /etc/motd "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/motd"
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client1.ovpn
#useradd -m -g users -s /bin/bash test
#echo "test:test" | chpasswd
echo "UPDATE AND INSTALL COMPLETE COMPLETE 99% BE PATIENT"
rm *.sh;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;
clear


# install vnstat gui
cd /home/vps/public_html/
wget https://raw.githubusercontent.com/tinasetina/9/master/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
sed -i "s/\$locale = 'en_US.UTF-8';/\$locale = 'en_US.UTF+8';/g" config.php
cd
clear
# Install BadVPN
apt-get -y install cmake make gcc
wget https://raw.githubusercontent.com/tinasetina/9/master/badvpn-1.999.127.tar.bz2
tar xf badvpn-1.999.127.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.127 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
cd

# install stunnel
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
pid = /stunnel.pid
client = no	
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 443
connect = 127.0.0.1:442
connect = 127.0.0.1:109
connect = 127.0.0.1:110
;[squid]
;accept = 8000
;connect = 127.0.0.1:3128
;connect = 127.0.0.1:80
;connect = 127.0.0.1:8080
END

#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

#konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

#Setting UFW
ufw allow ssh
ufw allow 1194/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw


# pendukung shc
cd
apt-get install yum
yum -y install make automake autoconf gcc gcc++
apt-get -y install build-essential
aptitude -y install build-essential
#shc file
cd
wget "https://raw.githubusercontent.com/tinasetina/9/master/shc-3.8.7.tgz"
tar xvfz shc-3.8.7.tgz
#cd shc-3.8.7
#make
clear
echo "=========================================================="
echo "-------------------Tanggal Expiry Date MENU----------------"
echo "##########################################################"
echo -e "Wajib di isi bos " 

echo -e "Contoh Format Tanggal: 30/07/2018 (2 digit/2 digit/4 digit)"
echo -e "Angka semua ya boss!"
echo ""
read -p "Silahkan Ketikan Tanggal exp date (menu): " deeniemenu
cd shc-3.8.7
make
./shc -e $deeniemenu -m "Maaf boss MENU ente sudah kadaluarsa silahkan hubungi admin " -f /usr/local/bin/menu
clear
#./shc -e $deeniemenu -f /usr/local/bin/menu
#./shc -f /usr/local/bin/menu
cd
mv /usr/local/bin/menu.x /usr/local/bin/menu
chmod +x /usr/local/bin/menu
cd
rm /usr/local/bin/menu.x.c

# hapus installan shc
rm -rf /root/shc-3.8.7
rm /root/shc-3.8.7.tgz

# Configure menu
wget https://raw.githubusercontent.com/Vpsee00/nine9/master/menu
chmod +x menu
./menu

#swap ram
wget http://xhome.tech/Debian9/swap-ram.sh
chmod +x swap-ram.sh
./swap-ram.sh

#bonus block torrent
wget http://xhome.tech/Debian9/torrent.sh
chmod +x torrent.sh
./torrent.sh

# Finishing
wget -O /etc/vpnfix.sh http://xhome.tech/Debian9/vpnfix.sh
chmod 777 /etc/vpnfix.sh
sed -i 's/exit 0//g' /etc/rc.local
echo "" >> /etc/rc.local
echo "bash /etc/vpnfix.sh" >> /etc/rc.local
echo "$ screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &" >> /etc/rc.local
echo "nohup ./cron.sh &" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
clear
# restart service
service ssh restart
service openvpn restart
service dropbear restart
service nginx restart
service php7.0-fpm restart
service webmin restart
service squid restart
service fail2ban restart
clear
# SELASAI SUDAH BOSS! ( AutoscriptByOrangKuatSabahanTerkini )
echo "========================================"  | tee -a log-install.txt
echo "ทำใช้ๆๆๆๆๆๆๆๆๆ เท่านั้น)"  | tee -a log-install.txt
echo "----------------------------------------"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "nginx : http://$myip:80"   | tee -a log-install.txt
echo "Webmin : http://$myip:10000/"  | tee -a log-install.txt
echo "ปลาหมึก : 8080"  | tee -a log-install.txt
echo "เปิดเอสเอ&สเอช : 22"  | tee -a log-install.txt
echo "วางหมี : 443"  | tee -a log-install.txt
echo "เปิดวีพีเอ็น  : TCP 1194 (พร้อม bug)"  | tee -a log-install.txt
echo "Fail2Ban : [on]"  | tee -a log-install.txt
echo "Timezone : Asia/Kuala_Lumpur"  | tee -a log-install.txt
echo "Menu : พิมพ์ menu เพื่อใช้ menu script"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------------------------------------"
echo "LOG INSTALL  --> /root/log-install.txt"
echo "----------------------------------------"
echo "========================================"  | tee -a log-install.txt
echo "      รีเซิฟทีนึง      " 
echo "========================================"  | tee -a log-install.txt
cat /dev/null > ~/.bash_history && history -c
