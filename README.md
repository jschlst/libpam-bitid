libpam-bitid
============

A PAM module to use a bitcoin address for credentials

Note: this is a work in progress leading up to release 1.0.0

# Build

1. ./autogen.sh
2. ./configure --prefix=/usr
3. make
4. sudo make install

# Install

1. Build and install this package.
2. Edit /etc/pam.d/login and add the lines from examples/login.diff
3. cp examples/bitcoin.access /etc/bitcoin.access
4. Edit /etc/bitcoin.access and include list of allowed addresses/username pairs

# Example
```
$ telnet localhost
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Ubuntu 13.10
bitcoin: 1LdT92GDvP96cuiDRnQPhG4yCigQfxzWpz
message: test
signature: HL/GMhEijPCs1ZW4n7cekKKLSHcioteMQU4yeS/VDy0xmErtExnWr83vg7q32ARCIJGF1DMQZfl/L4dYm2Z7MuU=
Last login: Fri May  9 23:28:37 PDT 2014 from localhost on pts/4
Welcome to Ubuntu 13.10 (GNU/Linux 3.11.0-12-generic x86_64)
 
btctest:~$
```
