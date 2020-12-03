#!/bin/bash

# LinuxgeV1.0  2020.12.5
# 适用于Linux服务器的自动强化脚本
#
# Linux哥
# www.linuxge.com

#提取了 Lynis 的很多建议
# www.cisofy.com/lynis
#主要提取于Internet Security CIS中心
# www.cisecurity.org

##############################################################################################################


source helpers.sh

##############################################################################################################

f_banner(){
echo
echo "
 LinuxgeV1.0  2020.12.5
适用于debian 10服务器的自动强化脚本
##############################
Linux哥制作
博客：https://www.linuxge.com
由Linux哥开发 "
echo
echo

}

##############################################################################################################

# 检查是否以root用户身份运行

clear
f_banner


check_root() {
if [ "$USER" != "root" ]; then
      echo "没有权限"
      echo "此脚本只能由root运行"
      exit
else
      clear
      f_banner
      jshielder_home=$(pwd)
      cat templates/texts/welcome
fi
}

##############################################################################################################

# 安装依赖项
# 所需的前提条件将在此处设置
install_dep(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m 设置一些先决条件"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   add-apt-repository universe
   say_done
}

##############################################################################################################

# 配置主机名
config_host() {
echo -n " ¿您是否希望设置主机名? (y/n): "; read config_host
if [ "$config_host" == "y" ]; then
    serverip=$(__get_ip)
    echo " 输入名称以标识此服务器 :"
    echo -n " (例如：myserver): "; read host_name
    echo -n " ¿请输入您的域名?: "; read domain_name
    echo $host_name > /etc/hostname
    hostname -F /etc/hostname
    echo "127.0.0.1    localhost.localdomain      localhost" >> /etc/hosts
    echo "$serverip    $host_name.$domain_name    $host_name" >> /etc/hosts
    #为未经授权的访问创建法律横幅
    echo ""
    echo "创建合法横幅以进行未经授权的访问"
    spinner
    cat templates/motd > /etc/motd
    cat templates/motd > /etc/issue
    cat templates/motd > /etc/issue.net
    sed -i s/server.com/$host_name.$domain_name/g /etc/motd /etc/issue /etc/issue.net
    echo "OK "
fi
    say_done
}

##############################################################################################################

# 配置时区
config_timezone(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m 现在，我们将配置时区"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   sleep 10
   dpkg-reconfigure tzdata
   say_done
}

##############################################################################################################

# 更新系统，安装sysv-rc-conf工具
update_system(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m 更新系统"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt update
   apt upgrade -y
   apt dist-upgrade -y
   say_done
}

##############################################################################################################

# 设置更严格的UMASK
restrictive_umask(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m 将UMASK设置为更严格的值（027）"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   cp templates/login.defs /etc/login.defs
   echo ""
   echo "OK"
   say_done
}

#############################################################################################################

#禁用未使用的文件系统

unused_filesystems(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m 禁用未使用的文件系统"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf
   echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf
   echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
   echo "install hfsplus /bin/true" >>  /etc/modprobe.d/hfsplus.conf
   echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
   echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
   echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf
   echo " OK"
   say_done
}

##############################################################################################################

uncommon_netprotocols(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m 禁用不常见的网络协议"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
   echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
   echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
   echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf
   echo " OK"
   say_done

}

##############################################################################################################

# 创建特权用户
admin_user(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 我们现在将创建一个新用户"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " 输入新的用户名: "; read username
    adduser $username
    say_done
}

##############################################################################################################

# 生成RSA密钥的指令
rsa_keygen(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 生成RSA密钥对的说明"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    serverip=$(__get_ip)
    echo " *** 如果您没有公共RSA密钥，请生成一个 ***"
    echo "     遵循指示并在完成后按Enter"
    echo "     接收新指令"
    echo " "
    echo "    运行以下命令"
    echo -n "     a) ssh-keygen -t rsa -b 4096 "; read foo1
    echo -n "     b) cat /home/$username/.ssh/id_rsa.pub >> /home/$username/.ssh/authorized_keys "; read foo2
    say_done
}
##############################################################################################################

# 移动生成的公钥
rsa_keycopy(){
    echo " 运行以下命令以复制密钥"
    echo " 完成后按ENTER "
    echo " ssh-copy-id -i $HOME/.ssh/id_rsa.pub $username@$serverip "
    say_done
}
##############################################################################################################

#保护/ tmp文件夹
secure_tmp(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 保护/ tmp文件夹"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n " ¿在初始安装过程中是否创建了单独的/tmp分区? (y/n): "; read tmp_answer
  if [ "$tmp_answer" == "n" ]; then
      echo "我们将为/tmp目录创建一个文件系统，并设置适当的权限 "
      spinner
      dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000
      mkdir /tmpbackup
      cp -Rpf /tmp /tmpbackup
      mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
      chmod 1777 /tmp
      cp -Rpf /tmpbackup/* /tmp/
      rm -rf /tmpbackup
      echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
      sudo mount -o remount /tmp
      say_done
  else
      echo "请记住在/etc/fstab中设置适当的权限"
      echo ""
      echo "例:"
      echo ""
      echo "/dev/sda4   /tmp   tmpfs  loop,nosuid,noexec,rw  0 0 "
      say_done
  fi
}

##############################################################################################################

# 安全SSH
secure_ssh(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 保护SSH"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " 保护SSH..."
    spinner
    sed s/USERNAME/$username/g templates/sshd_config > /etc/ssh/sshd_config; echo "OK"
    chattr -i /home/$username/.ssh/authorized_keys
    service ssh restart
    say_done
}

##############################################################################################################

# 设置IPTABLES规则
set_iptables(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 设定IPTABLE规则"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " 设置iptables规则..."
    spinner
    sh templates/iptables.sh
    cp templates/iptables.sh /etc/init.d/
    chmod +x /etc/init.d/iptables.sh
    ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
    say_done
}

##############################################################################################################
# 安装fail2ban
    # 要删除Fail2Ban规则，请使用:
    # iptables -D fail2ban-ssh -s IP -j DROP
install_fail2ban(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装Fail2Ban"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install sendmail
    apt install fail2ban
    say_done
}

##############################################################################################################

# 安装，配置和优化MySQL
install_secure_mysql(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装，配置和优化MySQL"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install mysql-server
    echo ""
    echo -n " 配置MySQL............ "
    spinner
    cp templates/mysql /etc/mysql/mysqld.cnf; echo " OK"
    mysql_secure_installation
    cp templates/usr.sbin.mysqld /etc/apparmor.d/local/usr.sbin.mysqld
    service mysql restart
    say_done
}

##############################################################################################################

# 安装Apache
install_apache(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installing Apache Web服务器"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install apache2
  say_done
}

##############################################################################################################

# 安装Nginx
install_nginx(){
  clear
  f_banner 
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 安装NginX Web服务器"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "deb http://nginx.org/packages/ubuntu/ bionic nginx" >> /etc/apt/sources.list
  echo "deb-src http://nginx.org/packages/ubuntu/ bionic nginx" >> /etc/apt/sources.list
  curl -O https://nginx.org/keys/nginx_signing.key && apt-key add ./nginx_signing.key
  apt update
  apt install nginx
  say_done
}

##############################################################################################################

#为NginX编译ModSecurity

compile_modsec_nginx(){
  clear
  f_banner 
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 安装先决条件并为NginX编译ModSecurity"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""

apt install bison flex make automake gcc pkg-config libtool doxygen git curl zlib1g-dev libxml2-dev libpcre3-dev build-essential libyajl-dev yajl-tools liblmdb-dev rdmacm-utils libgeoip-dev libcurl4-openssl-dev liblua5.2-dev libfuzzy-dev openssl libssl-dev

cd /opt/
git clone https://github.com/SpiderLabs/ModSecurity

cd ModSecurity
git checkout v3/master
git submodule init
git submodule update

./build.sh
./configure
make
make install

cd ..

nginx_version=$(dpkg -l |grep nginx | awk '{print $3}' | cut -d '-' -f1)

wget http://nginx.org/download/nginx-$nginx_version.tar.gz
tar xzvf nginx-$nginx_version.tar.gz

git clone https://github.com/SpiderLabs/ModSecurity-nginx

cd nginx-$nginx_version/

./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx
make modules

cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules/

cd /etc/nginx/

mkdir /etc/nginx/modsec
cd /etc/nginx/modsec
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
mv /etc/nginx/modsec/owasp-modsecurity-crs/crs-setup.conf.example /etc/nginx/modsec/owasp-modsecurity-crs/crs-setup.conf

cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf

echo "Include /etc/nginx/modsec/modsecurity.conf" >> /etc/nginx/modsec/main.conf
echo "Include /etc/nginx/modsec/owasp-modsecurity-crs/crs-setup.conf" >> /etc/nginx/modsec/main.conf
echo "Include /etc/nginx/modsec/owasp-modsecurity-crs/rules/*.conf" >> /etc/nginx/modsec/main.conf

wget -P /etc/nginx/modsec/ https://github.com/SpiderLabs/ModSecurity/raw/v3/master/unicode.mapping
cd $jshielder_home

  clear
  f_banner 
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 为NginX配置ModSecurity"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  spinner
  cp templates/nginx /etc/nginx/nginx.conf
  cp templates/nginx_default /etc/nginx/conf.d/default.conf
  service nginx restart
  say_done

}

##############################################################################################################

# 安装，配置和优化PHP
install_secure_php(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装，配置和优化PHP"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install -y php php-cli php-pear
    apt install -y php-mysql python-mysqldb libapache2-mod-php7.2
    echo ""
    echo -n " 替换php.ini..."
    spinner
    cp templates/php /etc/php/7.2/apache2/php.ini; echo " OK"
    cp templates/php /etc/php/7.2/cli/php.ini; echo " OK"
    service apache2 restart
    say_done
}

##############################################################################################################

# 为Nginx安装，配置和优化PHP
install_secure_php_nginx(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 为NginX安装，配置和优化PHP"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install -y php-fpm php-mysql
    echo ""
    echo -n " 删除php.ini上的不安全配置..."
    spinner
    sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php/7.2/fpm/php.ini; echo " OK"
    service php7.2-fpm restart
    say_done
}

##############################################################################################################

# 安装ModSecurity
install_modsecurity(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装ModSecurity"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install libxml2 libxml2-dev libxml2-utils
    apt install libaprutil1 libaprutil1-dev
    apt install libapache2-mod-security2
    service apache2 restart
    say_done
}

##############################################################################################################

# 配置OWASP ModSecurity核心规则集（CRS3）
set_owasp_rules(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 设置OWASP ModSecurity核心规则集（CRS3）"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

    #用于 /usr/share/modsecurity-crs/base_rules/中的档案*
     #   do ln -s $archivo /usr/share/modsecurity-crs/activated_rules/
    #done

    #用于 /usr/share/modsecurity-crs/optional_rules/中的档案*
    #    do ln -s $archivo /usr/share/modsecurity-crs/activated_rules/
    #done
    spinner
    echo "OK"

    sed s/SecRuleEngine\ DetectionOnly/SecRuleEngine\ On/g /etc/modsecurity/modsecurity.conf-recommended > salida
    mv salida /etc/modsecurity/modsecurity.conf

    echo 'SecServerSignature "AntiChino Server 1.0.4 LS"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
    echo 'Header set X-Powered-By "Plankalkül 1.0"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
    echo 'Header set X-Mamma "Mama mia let me go"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf

    a2enmod headers
    service apache2 restart
    say_done
}

##############################################################################################################

# 配置和优化Apache
secure_optimize_apache(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 优化Apache"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    cp templates/apache /etc/apache2/apache2.conf
    echo " -- 启用Mod_Rewrite"
    spinner
    a2enmod rewrite
    service apache2 restart
    say_done
}

##############################################################################################################

# 安装Mod_Evasive
install_modevasive(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装ModEvasive"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " 输入电子邮件以接收警报 "; read inbox
    apt install libapache2-mod-evasive
    mkdir /var/log/mod_evasive
    chown www-data:www-data /var/log/mod_evasive/
    sed s/MAILTO/$inbox/g templates/mod-evasive > /etc/apache2/mods-available/mod-evasive.conf
    service apache2 restart
    say_done
}

##############################################################################################################

# 安装 Mod_qos/spamhaus
install_qos_spamhaus(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装 Mod_Qos/Spamhaus"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt -y install libapache2-mod-qos
    cp templates/qos /etc/apache2/mods-available/qos.conf
    apt -y install libapache2-mod-spamhaus
    cp templates/spamhaus /etc/apache2/mods-available/spamhaus.conf
    service apache2 restart
    say_done
}

##############################################################################################################
# 配置fail2ban
config_fail2ban(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 配置Fail2Ban"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " 配置Fail2Ban......"
    spinner
    sed s/MAILTO/$inbox/g templates/fail2ban > /etc/fail2ban/jail.local
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.conf
    /etc/init.d/fail2ban restart
    say_done
}

##############################################################################################################

# 安装其他软件包
additional_packages(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装其他软件包"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Install tree............."; apt install tree
    echo "Install Python-MySQLdb..."; apt install python-mysqldb
    echo "Install WSGI............."; apt install libapache2-mod-wsgi
    echo "Install PIP.............."; apt install python-pip
    echo "Install Vim.............."; apt install vim
    echo "Install Nano............."; apt install nano
    echo "Install pear............."; apt install php-pear
    echo "Install DebSums.........."; apt install debsums
    echo "Install apt-show-versions"; apt install apt-show-versions
    echo "Install PHPUnit..........";
    pear config-set auto_discover 1
    mv phpunit-patched /usr/share/phpunit
    echo include_path = ".:/usr/share/phpunit:/usr/share/phpunit/PHPUnit" >> /etc/php/7.2/cli/php.ini
    echo include_path = ".:/usr/share/phpunit:/usr/share/phpunit/PHPUnit" >> /etc/php/7.2/apache2/php.ini
    service apache2 restart
    say_done
}

##############################################################################################################

# 调整和安全内核
tune_secure_kernel(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 调整和保护Linux内核"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " 保护Linux内核"
    spinner
    echo "* hard core 0" >> /etc/security/limits.conf
    cp templates/sysctl.conf /etc/sysctl.conf; echo " OK"
    cp templates/ufw /etc/default/ufw
    sysctl -e -p
    say_done
}

##############################################################################################################

# 安装RootKit Hunter
install_rootkit_hunter(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装RootKit Hunter"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Rootkit Hunter是一种扫描工具，可确保您不干净。 该工具通过运行类似的测试来扫描rootkit，后门程序和本地漏洞:

          - MD5 哈希比较
          - 查找rootkit使用的默认文件
          - 二进制文件的文件权限错误
          - 在LKM和KLD模块中查找可疑的字符串
          - 寻找隐藏文件
          - 纯文本和二进制文件中的可选扫描 "
    sleep 1
    cd rkhunter-1.4.6/
    sh installer.sh --layout /usr --install
    cd ..
    rkhunter --update
    rkhunter --propupd
    echo ""
    echo " ***运行RootKit Hunter ***"
    echo "     rkhunter -c --enable all --disable none"
    echo "     详细报告 /var/log/rkhunter.log"
    say_done
}

##############################################################################################################

# 调整文件编辑器环境变量
tune_nano_vim_bashrc(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Tunning bashrc, nano and Vim"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

# Tune .bashrc
    echo "Tunning .bashrc......"
    spinner
    cp templates/bashrc-root /root/.bashrc
    cp templates/bashrc-user /home/$username/.bashrc
    chown $username:$username /home/$username/.bashrc
    echo "OK"


# Tune Vim
    echo "Tunning Vim......"
    spinner
    tunning vimrc
    echo "OK"


# Tune Nano
    echo "Tunning Nano......"
    spinner
    tunning nanorc
    echo "OK"
    say_done
}

##############################################################################################################

# 添加每日更新Cron更新系统
daily_update_cronjob(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 添加每日系统更新Cron更新系统"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "创建每日Cron更新系统"
    spinner
    job="@daily apt update; apt dist-upgrade -y"
    touch job
    echo $job >> job
    crontab job
    rm job
    say_done
}

##############################################################################################################

# 安装PortSentry
install_portsentry(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装PortSentry"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install portsentry
    mv /etc/portsentry/portsentry.conf /etc/portsentry/portsentry.conf-original
    cp templates/portsentry /etc/portsentry/portsentry.conf
    sed s/tcp/atcp/g /etc/default/portsentry > salida.tmp
    mv salida.tmp /etc/default/portsentry
    /etc/init.d/portsentry restart
    say_done
}

##############################################################################################################

# 安装和配置artillery
install_artillery (){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 克隆git仓库和安装 Artillery"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    git clone https://github.com/BinaryDefense/artillery
    cd artillery/
    python setup.py
    cd ..
    echo ""
    echo "请不要忘记为artillery设置防火墙规则"
    echo ""
    echo "Artillery 配置文件是 /var/artillery/config"
    say_done  
}
##############################################################################################################

# 其他强化步骤
additional_hardening(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 运行其他强化步骤"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "运行其他强化步骤...."
    spinner
    echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    #删除AT并限制Cron
    apt purge at
    apt install -y libpam-cracklib
    echo ""
    echo " 确保Cron "
    spinner
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
    echo ""
    echo -n " 您是否要禁用此服务器的USB支持? (y/n): " ; read usb_answer
    if [ "$usb_answer" == "y" ]; then
       echo ""
       echo "禁用USB支持"
       spinner
       echo "将USB存储列入黑名单" | sudo tee -a /etc/modprobe.d/blacklist.conf
       update-initramfs -u
       echo "OK"
       say_done
    else
       echo "OK"
       say_done
    fi
}

##############################################################################################################

# 安装unhide
install_unhide(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装unhide"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Unhide是一种取证工具，可以通过rootkits/LKM或其他隐藏技术来查找隐藏的进程和TCP / UDP端口."
    sleep 1
    apt -y install unhide
    echo ""
    echo " 取消隐藏是用于检测隐藏进程的工具 "
    echo " 有关该工具的更多信息，请使用手册页 "
    echo " man unhide "
    say_done
}

##############################################################################################################

# 安装 Tiger
#Tiger 和审计与入侵检测系统
install_tiger(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 安装 Tiger"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Tiger是可同时用作安全审核和入侵检测系统的安全工具"
    sleep 1
    apt -y install tiger
    echo ""
    echo " 有关该工具的更多信息，请使用手册页 "
    echo " man tiger "
    say_done
}

##############################################################################################################

#安装PSAD
#PSAD主动监视防火墙日志以确定是否正在进行扫描或攻击
install_psad(){
clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m 安装PSAD"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo " PSAD是一款软件，可以主动监视您的防火墙日志以确定是否进行扫描
       或攻击事件正在进行中。 它可以发出警报并采取措施阻止威胁

       NOTE:
       如果仅运行此功能，则必须启用iptables日志记录

       iptables -A INPUT -j LOG
       iptables -A FORWARD -j LOG

       "
echo ""
echo -n " 您是否要安装PSAD (Recommended)? (y/n): " ; read psad_answer
if [ "$psad_answer" == "y" ]; then
     echo -n " 输入电子邮件地址以接收PSAD警报: " ; read inbox1
     apt install psad
     sed -i s/INBOX/$inbox1/g templates/psad.conf
     sed -i s/CHANGEME/$host_name.$domain_name/g templates/psad.conf  
     cp templates/psad.conf /etc/psad/psad.conf
     psad --sig-update
     service psad restart
     echo "安装和配置完成"
     echo "针对检测到的事件运行服务psad状态"
     echo ""
     say_done
else
     echo "OK"
     say_done
fi
}

##############################################################################################################


# 禁用编译器
disable_compilers(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 禁用编译器"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "禁用编译器....."
    spinner
    chmod 000 /usr/bin/as >/dev/null 2>&1
    chmod 000 /usr/bin/byacc >/dev/null 2>&1
    chmod 000 /usr/bin/yacc >/dev/null 2>&1
    chmod 000 /usr/bin/bcc >/dev/null 2>&1
    chmod 000 /usr/bin/kgcc >/dev/null 2>&1
    chmod 000 /usr/bin/cc >/dev/null 2>&1
    chmod 000 /usr/bin/gcc >/dev/null 2>&1
    chmod 000 /usr/bin/*c++ >/dev/null 2>&1
    chmod 000 /usr/bin/*g++ >/dev/null 2>&1
    spinner
    echo ""
    echo " 如果您想使用它们，只需更改权限"
    echo " 例: chmod 755 /usr/bin/gcc "
    echo " OK"
    say_done
}

##############################################################################################################

# 限制对Apache Config文件的访问
apache_conf_restrictions(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 限制对Apache Config文件的访问"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " 限制对Apache Config文件的访问......"
    spinner
     chmod 750 /etc/apache2/conf* >/dev/null 2>&1
     chmod 511 /usr/sbin/apache2 >/dev/null 2>&1
     chmod 750 /var/log/apache2/ >/dev/null 2>&1
     chmod 640 /etc/apache2/conf-available/* >/dev/null 2>&1
     chmod 640 /etc/apache2/conf-enabled/* >/dev/null 2>&1
     chmod 640 /etc/apache2/apache2.conf >/dev/null 2>&1
     echo " OK"
     say_done
}

##############################################################################################################

  # 其他安全配置
  #启用无人参与的自动安全更新
  unattended_upgrades(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 启用无人参与的自动安全更新"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n " ¿您是否希望启用无人参与的自动安全更新? (y/n): "; read unattended
  if [ "$unattended" == "y" ]; then
      dpkg-reconfigure -plow unattended-upgrades
  else
      clear
  fi
}

##############################################################################################################

# 启用流程会计acct
enable_proc_acct(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 启用流程会计acct"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install acct
  touch /var/log/wtmp
  echo "OK"
}

##############################################################################################################

#安装并启用审核auditd

install_auditd(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 安装 auditd"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install auditd

  # 使用CIS Benchmark配置
  
  #确保启用对在审核之前启动的过程的审核
  echo ""
  echo "对在审核之前开始的过程启用审核"
  spinner
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub
  update-grub

  echo ""
  echo "配置审核的规则"
  spinner

  cp templates/audit-CIS.rules /etc/audit/rules.d/audit.rules

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
  "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
  -k privileged" } ' >> /etc/audit/rules.d/audit.rules

  echo " " >> /etc/audit/rules.d/audit.rules
  echo "#End of Audit Rules" >> /etc/audit/rules.d/audit.rules
  echo "-e 2" >>/etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  service auditd restart
  echo "OK"
  say_done
}
##############################################################################################################

#安装并启用sysstat

install_sysstat(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 安装并启用sysstat"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install sysstat
  sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
  service sysstat start
  echo "OK"
  say_done
}

##############################################################################################################

#安装ArpWatch

install_arpwatch(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m ArpWatch安装"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "ArpWatch是用于监视系统上ARP流量的工具。 它生成观察到的IP和MAC配对的日志."
  echo ""
  echo -n " 您是否要在此服务器上安装ArpWatch? (y/n): " ; read arp_answer
  if [ "$arp_answer" == "y" ]; then
     echo "安装ArpWatch"
     spinner
     apt install -y arpwatch
     systemctl enable arpwatch.service
     service arpwatch start
     echo "OK"
     say_done
  else
     echo "OK"
     say_done
  fi
}

##############################################################################################################

set_grubpassword(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m GRUB引导程序密码"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "建议在GRUB引导加载程序上设置密码，以防止更改引导配置（例如，在没有密码的单用户模式下引导）"
  echo ""
  echo "#####注意######"
  echo "在此处设置密码后每次系统启动就会要求输入密码否则会无法启动系统，更无法进入系统，如果想启动系统不需要输入密码请一定要查看说明文件，不要乱设置"
  echo ""
  echo -n " 您是否要设置GRUB Bootloader密码? (y/n): " ; read grub_answer
  if [ "$grub_answer" == "y" ]; then
    grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
    grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
    echo " set superusers="root" " >> /etc/grub.d/40_custom
    echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
    rm grubpassword.tmp
    update-grub
    echo "在每次启动时，输入root用户和您刚设置的密码"
    echo "OK"
    say_done
  else
    echo "OK"
    say_done
  fi

echo -e ""
echo -e "保护启动设置"
spinner
sleep 2
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
say_done

}    

##############################################################################################################

file_permissions(){
 clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m 在关键系统文件上设置文件权限"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  spinner
  sleep 2
  
  chown root:root /etc/systemd/system/aidecheck.*
  chmod 0644 /etc/systemd/system/aidecheck.*
  
  chown root:root /boot/grub/grub.cfg
  chmod og-rwx /boot/grub/grub.cfg
  
  chown root:root /etc/motd
  chmod u-x,go-wx /etc/motd
  
  chown root:root /etc/issue
  chmod u-x,go-wx /etc/issue
  
  chown root:root /etc/issue.net
  chmod u-x,go-wx /etc/issue.net
  
  chown root:root /etc/cron.hourly
  chmod og-rwx /etc/cron.hourly
  
  chown root:root /etc/cron.daily
  chmod og-rwx /etc/cron.daily
  
  chown root:root /etc/cron.weekly
  chmod og-rwx /etc/cron.weekly
  chown root:root /etc/cron.monthly
  chmod og-rwx /etc/cron.monthly
  
  chown root:root /etc/cron.d
  chmod og-rwx /etc/cron.d
  
  chown root:root /etc/cron.allow
  chmod g-wx,o-rwx /etc/cron.allow
  chown root:root /etc/at.allow
  chmod g-wx,o-rwx /etc/at.allow
  
  chown root:root /etc/ssh/sshd_config
  chmod og-rwx /etc/ssh/sshd_config
  
  chown root:root /etc/passwd
  chmod 644 /etc/passwd
  
  chown root:root /etc/gshadow-
  chown root:shadow /etc/gshadow-
  chmod o-rwx,g-wx /etc/gshadow-
  
  chmod o-rwx,g-wx /etc/shadow
  chown root:shadow /etc/shadow
  
  chown root:root /etc/group
  chmod 644 /etc/group
  
   chown root:root /etc/passwd-
   chmod u-x,go-rwx /etc/passwd-
   
   chown root:shadow /etc/shadow-
   chmod u-x,go-rwx /etc/shadow-
   
   chown root:root /etc/group-
   chmod u-x,go-rwx /etc/group-
   
   chown root:shadow /etc/gshadow
   chmod o-rwx,g-wx /etc/gshadow
   
  echo -e ""
  echo -e "在所有世界可写目录上设置粘滞位"
  sleep 2
  spinner

  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

  echo " OK"
  say_done

}
##############################################################################################################

# 重新启动服务器
reboot_server(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 最后一步"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    sed -i s/USERNAME/$username/g templates/texts/bye
    sed -i s/SERVERIP/$serverip/g templates/texts/bye
    cat templates/texts/bye
    echo -n " ¿您是否可以使用$username通过SSH连接到服务器? (y/n): "; read answer
    if [ "$answer" == "y" ]; then
        reboot
    else
        echo "服务器不会重新启动"
        echo "Bye."
    fi
}

##################################################################################################################

clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m 选择所需的选项"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1. LAMP部署"
echo "2. LNMP部署"
echo "3. 使用Apache进行反向代理部署"
echo "4. 通用（没有WebServer或DBServer）"
echo "5. 使用SecureWPDeployer或JSDeployer脚本运行"
echo "6. 自定义运行（仅运行所需的选项）"
echo "7. CIS基准强化"
echo "8. 退出"
echo

read choice

case $choice in

1)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_secure_mysql
install_apache
install_secure_php
install_modsecurity
set_owasp_rules
secure_optimize_apache
install_modevasive
install_qos_spamhaus
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
apache_conf_restrictions
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;


2)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_secure_mysql
install_nginx
compile_modsec_nginx
install_secure_php_nginx
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;

3)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_apache
install_modsecurity
set_owasp_rules
secure_optimize_apache
install_modevasive
install_qos_spamhaus
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
apache_conf_restrictions
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;

4)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
unattended_upgrades
enable_proc_acct
install_auditd
install_arpwatch
set_grubpassword
file_permissions
;;


5)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_secure_mysql
install_apache
install_secure_php
install_modsecurity
set_owasp_rules
secure_optimize_apache
install_modevasive
install_qos_spamhaus
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
apache_conf_restrictions
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
;;

6)

menu=""
until [ "$menu" = "34" ]; do

clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m 选择所需的选项"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1. 配置主机名，创建合法标语，更新主机文件"
echo "2. 配置时区"
echo "3. 更新系统"
echo "4. 创建管理员用户"
echo "5. 生成和移动私钥/公钥对的说明"
echo "6. 安全SSH配置"
echo "7. 设置限制性IPTable规则"
echo "8. 安装和配置Fail2Ban"
echo "9. 安装，优化和保护Apache"
echo "10. 使用ModSecurity Module安装Nginx并设置OwaspRules"
echo "11. 使用PHP设置Nginx Vhost"
echo "12. 设置Nginx虚拟主机"
echo "13. 为Apache服务器安装并保护PHP"
echo "14. 为Nginx服务器安装并保护PHP"
echo "15. 安装ModSecurity（Apache）并设置Owasp规则"
echo "16. 安装Mod_Evasive"
echo "17. 安装ModQos和SpamHaus"
echo "18. 调整和保护Linux内核"
echo "19. 安装RootKit Hunter"
echo "20. 调整 Vim, Nano, Bashrc"
echo "21. 安装PortSentry"
echo "22. 安全tty，root home，grub配置，cron"
echo "23. 安装 Unhide"
echo "24. 安装 Tiger"
echo "25. 禁用编译器"
echo "26. 启用无人值守系统自动升级"
echo "27. 启用流程会计acct"
echo "28. 安装PHP Suhosin（暂时禁用）"
echo "29. 安装并保护MySQL"
echo "30. 设置更严格的UMASK值（027）"
echo "31. 安全/tmp目录"
echo "32. 安装PSAD IDS"
echo "33. 设置GRUB Bootloader密码"
echo "34. 退出"
echo " "

read menu
case $menu in

1)
config_host
;;

2)
config_timezone
;;

3)
update_system
;;

4)
admin_user
;;

5)
rsa_keygen
rsa_keycopy
;;

6)
echo "key Pair must be created "
echo "What user will have access via SSH? " ; read username
rsa_keygen
rsa_keycopy
secure_ssh
;;

7)
set_iptables
;;

8)
echo "Type Email to receive Alerts: " ; read inbox
install_fail2ban
config_fail2ban
;;

9)
install_apache
secure_optimize_apache
apache_conf_restrictions
;;

10)
install_nginx_modsecurity
set_nginx_modsec_OwaspRules
;;

11)
set_nginx_vhost
;;


12)
set_nginx_vhost_nophp
;;

13)
install_secure_php
;;

14)
install_php_nginx
;;

15)
install_modsecurity
set_owasp_rules
;;

16)
install_modevasive
;;

17)
install_qos_spamhaus
;;

18)
tune_secure_kernel
;;

19)
install_rootkit_hunter
;;

20)
tune_nano_vim_bashrc
;;

21)
install_portsentry
;;

22)
additional_hardening
;;

23)
install_unhide
;;

24)
install_tiger
;;

25)
disable_compilers;
;;

26)
unattended_upgrades
;;

27)
enable_proc_acct
;;

#28)
#install_phpsuhosin
#;;

29)
install_secure_mysql
;;

30)
restrictive_umask
;;

31)
secure_tmp
;;

32)
install_psad
;;

33)
set_grubpassword
;;

34)
break ;;

*) ;;

esac
done
;;

7)
chmod +x jshielder-CIS.sh
./jshielder-CIS.sh
;;


8)
exit 0
;;

esac
##############################################################################################################
