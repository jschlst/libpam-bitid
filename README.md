libpam-bitid
============

A PAM module to use a bitcoin address for credentials

Note: this is a work in progress leading up to release 1.0.0

## Build

1. ./autogen.sh
2. ./configure --prefix=/usr
3. make
4. sudo make install

## Install

1. Follow Build steps in section above for this package.
2. Edit /etc/pam.d/login and add the lines from examples/login.diff
3. cp examples/bitcoin.access /etc/bitcoin.access
4. Edit /etc/bitcoin.access and include list of allowed address/username pairs

## Example
```
$ telnet localhost
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Ubuntu 13.10
bitcoin: 1DvRd44mD8EuCcym8zymYzabvmozwZ5r8G
challenge message: test 
signature: Gw4YdpEAyDqTtLVYn6/0aH6Qg9fHjpX1+MTxJKMZgppSOI9e0/5rY6T23NpW7QB52tIz3EkjTkVmn7Pe3BZn3Aw=
Last login: Wed May 21 00:01:16 PDT 2014 from localhost on pts/8
Welcome to Ubuntu 13.10 (GNU/Linux 3.11.0-12-generic x86_64)
 
btctest:~$
```

## Documentation
* BitID protocol specification (https://github.com/bitid/bitid)
* Linux-PAM (http://www.linux-pam.org)
* Bitcoin protocol specification (https://en.bitcoin.it/wiki/Protocol_specification)
