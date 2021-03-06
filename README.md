libpam-bitid
============

A PAM module to use a bitcoin address for credentials.

This module is an implementation of the BitID protocol.

Currently only console and telnet login are supported.

## Download
Current release:
* [libpam-bitid_0.1.0_amd64.deb](https://github.com/angrycod/libpam-bitid/raw/master/releases/debian/libpam-bitid_0.1.0_amd64.deb)
* [libpam-bitid-0.1.0.tar.bz2](https://github.com/angrycod/libpam-bitid/raw/master/releases/libpam-bitid-0.1.0.tar.bz2)

Releases are archived in the git repository:
* [Source tar-balls](releases)
* [Ubuntu/debian packages](releases/debian)
* Note: select the file and then select "RAW" button to start download.

## Requires
- autoconfig
- libtool

## Build
1. `git clone https://github.com/angrycod/libpam-bitid.git`
2. `cd libpam_bitid`
3. `./autogen.sh`
4. `./configure --prefix=/usr`
5. `make`

## Install
1. `sudo make install`
2. `sudo cp examples/bitid.access /etc/bitid.access`
3. `sudo vi /etc/pam.d/login` Edit to add the lines from examples/login.diff

#### Ubuntu/debian install
1. `sudo dpkg -i libpam-bitid_0.1.0_amd64.deb`

## Configuration
`vi /etc/bitid.access` Edit to include your list of allowed address/username pairs

```
# bitid.access:
# List of users allowed access using login by bitcoin address
#
# format:
# bitcoin-address, username
1DvRd44mD8EuCcym8zymYzabvmozwZ5r8G, btctest
```

`vi /etc/pam.d/login` Edit to allow bitid login using telnet:

Add this line at the very top:
`auth       optional pam_bitid.so file=/etc/bitid.access`

And comment out this line:
`# @include common-auth`

If `common-auth` is still enabled then pam will try and do a unix login after doing the bitid login.

## Logs
Check `/var/log/auth.log` on Ubuntu for output of libpam-bitid module.

Upon successful bitid authentication you will see messages from pam_bitid.
```
pam_bitid(login:auth): user: btctest allowed access from: 1DvRd44mD8EuCcym8zymYzabvmozwZ5r8G
```

## Testing example configuration
It's clunky, but for testing this select the address in electrum and sign the challenge
message provided by the pam-bitid login with that. 

To get a login prompt, `telnet 127.0.0.1` and then enter your bitcoin address.

```
$ telnet localhost
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Ubuntu 14.04.1 LTS
bitcoin address: 1DvRd44mD8EuCcym8zymYzabvmozwZ5r8G
challenge message: dbcbd542b29a3c4298651035ae6eaed3
signature: HE8DDp4eAEy61417XTPAQTOqPBcLP2h0Y0sTB9hfFILCv8ZpLzdH6dh/z6+o7A4VwwjM1Qq2SFVcgyf7U51JhdE=
Last login: Wed May 21 18:42:01 PDT 2014 from localhost on pts/17
Welcome to Ubuntu 13.10 (GNU/Linux 3.11.0-12-generic x86_64)
 
btctest:~$
```

## Notes:
* Signatures are in electrum format, so signature will not be valid if using another format. Many clients use the electrum format, so clients other than electrum may work okay.

## References
* [BitID protocol specification] (https://github.com/bitid/bitid)
* [Linux-PAM] (http://www.linux-pam.org)
* [Bitcoin protocol specification] (https://en.bitcoin.it/wiki/Protocol_specification)

## Credits
Jay Schulist <jayschulist@gmail.com>
