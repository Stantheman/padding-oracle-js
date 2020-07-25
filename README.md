# padding-oracle-js

A visualization of the Padding Oracle attack using Javascript.

## overview

This code runs "live" -- it uses the browser's crypto API (the subtle library)
to encrypt a string. The attack is run against that generated ciphertext without
peeking at the original text.

The original padding oracle attack paper can be found here:

https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf

The Hacker101 CTF has a great challenge to learn more about implementing this
attack.

