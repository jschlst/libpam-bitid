Uses: pam_sm_authenticate()

Fixme:
- [ ] test code
- [ ] cleanup prompt code, simplify
- [ ] option for bitid uri generation

Config file:
-[ ] Various example pam.d config files
-[ ] Install /etc/pam.d/bitid-auth file, root must use @include instead.
-[ ] allow retry on data entry error, re-prompt user for input on signature?
-[ ] setup login file so it falls back to default login.
-[ ] when enabled pam modules: pam_securetty.so pam_nologin.so cause 
     username login prompt instead of bitcoin after failed input attempt.

Testing:
-[ ] using various input string sizes, past max input.
-[ ] test by having bitid.access file missing

Later:
-[ ] Add ACSII QR code generation... 
     -[ ] http://asciiqr.com/
     -[ ] http://fukuchi.org/works/qrencode/qrencode-3.4.3.tar.gz
-[ ] enable a callback to allow using mobile device for signing from wallet
-[ ] option to check login against bitcoin balance.
-[ ] Announce on pam mailing list, freecode

Tasks completed:
-[x] use more complex nonce that includes 16 bytes from random() + time().
