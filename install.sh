yum install -y go
yum install -y libpcap
yum install -y libpcap-devel
yum install -y net-tools
yum install -y htop
yum install -y sysstat
cd /opt
git clone https://github.com/For-ACGN/fast-scanner
cd fast-scanner/cmd
go build -v -i -ldflags "-s -w" -o scanner
cd ../examples/socks5
go build -v -i -ldflags "-s -w" -o socks5