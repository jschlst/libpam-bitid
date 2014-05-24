Uses: pam_sm_authenticate()

Fixme:
- [ ] write test code
- [ ] option for bitid uri generation

Config file:
- [ ] Various example pam.d config files
- [ ] Install /etc/pam.d/bitid-auth file, root must use @include instead.
- [c] prompt allows retry, but data is not accepted as input.
      - this is other modules enabled calling pam_get_user(). Disable them in pam config file.
      - possibly set some variable to help reset it.
- [ ] setup pam.d/login so it falls back to default login.

Later:
- [ ] Add ASCII QR code generation... 
     - [ ] http://asciiqr.com/
     - [ ] http://fukuchi.org/works/qrencode/qrencode-3.4.3.tar.gz
- [ ] enable a callback to allow using mobile device for signing from wallet
- [ ] option to check login against bitcoin balance.
- [ ] Announce on pam mailing list, freecode

Tasks completed:
- [x] cleanup prompt code, simplify
- [x] when enabled pam modules: pam_securetty.so pam_nologin.so cause 
      username login prompt instead of bitcoin after failed input attempt.
- [x] test by having bitid.access file missing
- [x] using various input string sizes, past max input.
- [x] use more complex nonce that includes 16 bytes from random() + time().
