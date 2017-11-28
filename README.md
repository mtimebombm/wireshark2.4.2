#!/bin/sh
# wireshark2.4.2 
# 执行该脚本，编译最简单的tshark，并安装

./autogen.sh

#最前面的CFLAGS="-g -O0"是为了将编译选项改为O0，便于调试
CFLAGS="-g -O0" ./configure --disable-wireshark --disable-packet-editor  --disable-editcap --disable-capinfos --disable-captype --disable-mergecap --disable-reordercap --disable-text2pcap --disable-dftest --disable-randpkt --disable-dumpcap --disable-rawshark --disable-pcap-ng-default --disable-androiddump --disable-sshdump --disable-ciscodump --disable-randpktdump --disable-sharkd --disable-udpdump

#编译，耗时较长
make 
#安装
sudo make install 
#更新环境变量
sudo ldconfig

