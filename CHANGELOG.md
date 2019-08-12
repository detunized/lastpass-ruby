Version 1.6.0
-------------

- Changed the way the private keys are parsed
- OpenSSL 1.1.0 support
- Bug fixes

Version 1.5.0
-------------

- Fixed failing `get_iteraction_count`. POST parameters are moved from the query (URL) to the body.
- pbkdf2-ruby gem is no longer used as it was causing problems. Relying on built-in `OpenSSL::PKCS5.pbkdf2_hmac`
- Minimum supported Ruby version is 2.0.0
- Dependencies updated to their laters versions
- Travis CI fixed

Version 1.4.0
-------------

- Added device id (IMEI/UUID) support
- Log out after fetching the blob to close the newly open session on LP server to prevent triggering anti-hacking logic (hopefully)
- Verify that the recieved blob is marked with ENDM chunk and hasn't been truncated in the process


Version 1.3.0
-------------

- Added proxy support


Version 1.2.1
-------------

- Fixed the decryption bug on long shared folder names.


Version 1.2.0
-------------

- Server secure note support


Version 1.1.0
-------------

- Shared folder support


Version 1.0.1
-------------

- Ruby 2.0 compatibility


Version 1.0.0
-------------

- First public gem release
