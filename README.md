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
3. cp examples/bitid.access /etc/bitid.access
4. Edit /etc/bitid.access and include list of allowed address/username pairs

```
# bitid.access:
# List of users allowed access using login by bitcoin address
#
# format:
# bitcoin-address, username
# 1LdT92GDvP96cuiDRnQPhG4yCigQfxzWpz, btctest
```

## Example
```
$ telnet localhost
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Ubuntu 13.10
bitcoin address: 1DvRd44mD8EuCcym8zymYzabvmozwZ5r8G
challenge message: dbcbd542b29a3c4298651035ae6eaed3
signature: HE8DDp4eAEy61417XTPAQTOqPBcLP2h0Y0sTB9hfFILCv8ZpLzdH6dh/z6+o7A4VwwjM1Qq2SFVcgyf7U51JhdE=
Last login: Wed May 21 18:42:01 PDT 2014 from localhost on pts/17
Welcome to Ubuntu 13.10 (GNU/Linux 3.11.0-12-generic x86_64)
 
btctest:~$
```

## Documentation
* BitID protocol specification (https://github.com/bitid/bitid)
* Linux-PAM (http://www.linux-pam.org)
* Bitcoin protocol specification (https://en.bitcoin.it/wiki/Protocol_specification)
