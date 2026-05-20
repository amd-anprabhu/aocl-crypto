# Appendix

## Compiling OpenSSL from the source.

AOCL-Cryptography has been tested with OpenSSL versions 3.1.3 through 3.5.x. The example below uses OpenSSL 3.4.1, but you may use any supported version.

```bash
git clone https://github.com/openssl/openssl.git -b openssl-3.4.1
cd openssl
./Configure --prefix=/usr/local
make -j $(nproc --all)
sudo make install
```
