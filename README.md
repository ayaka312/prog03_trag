# prog03_trag


vcpkg x-update-baseline --add-initial-baseline


OPENSSH=/opt/openssh2
mkdir -p /opt/openssh2/dist/
cd ${OPENSSH}
wget http://zlib.net/zlib-1.2.11.tar.gz
tar xvfz zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure --prefix=${OPENSSH}/dist/ && make && make install
cd ${OPENSSH}
wget http://www.openssl.org/source/openssl-1.0.1e.tar.gz
tar xvfz openssl-1.0.1e.tar.gz
cd openssl-1.0.1e
./config --prefix=${OPENSSH}/dist/ && make && make install
cd ${OPENSSH}
wget http://ftp.eu.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.8p1.tar.gz
tar xvfz openssh-8.8p1.tar.gz
cd openssh-8.8p1
# Chỉnh sửa code để log user và password tại file auth-passwd.c 
./configure --prefix=${OPENSSH}/dist/ --with-zlib=${OPENSSH}/dist --with-ssl-dir=${OPENSSH}/dist/ && make && make install
