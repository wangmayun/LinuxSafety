#!/bin/bash


# LinuxgeV1.0
# 适用于Linux服务器的自动强化脚本
#
# Linux哥
# www.linuxge.com

#提取了 Lynis 的很多建议
# www.cisofy.com/lynis
#主要提取于Internet Security CIS中心

##############################################################################################################

f_banner(){
echo
echo "
 LinuxgeV1.0
适用于Linux服务器的自动强化脚本
Linux哥制作
博客：https://www.linuxge.com
由Linux哥开发 "
echo
echo

}

##############################################################################################################

#检查是否以root用户运行

if [ "$USER" != "root" ]; then
      echo "没有权限"
      echo "此脚本只能由root运行"
      exit
else
      clear
      f_banner
fi


menu=""
until [ "$menu" = "10" ]; do

clear
f_banner

echo
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m SELECT YOUR LINUX DISTRIBUTION"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "请选择您的系统版本"
echo "1. Ubuntu Server 16.04 LTS"
echo "2. Ubuntu Server 18.04 LTS"
echo "3. Linux CentOS 7 (Coming Soon)"
echo "4. Debian GNU/Linux 8 (Coming Soon)"
echo "5. Debian GNU/Linux 9 (Coming Soon)"
echo "6. Red Hat Linux 7 (Coming Soon)"
echo "7. Exit"
echo

read menu
case $menu in

1)
cd UbuntuServer_16.04LTS/
chmod +x jshielder.sh
./jshielder.sh
;;

2)
cd UbuntuServer_18.04LTS/
chmod +x jshielder.sh
./jshielder.sh
;;

8)
break
;;

*) ;;

esac
done
