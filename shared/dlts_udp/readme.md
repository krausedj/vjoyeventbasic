# SockDtlsUdp
A simple implementation of a socket using OpenSSL DTLS (Datagram TLS)

## Why
I need a cheap way to have public ports open on a server, and do not want to use TCP, but instead UDP for my usecases.  I need access from C, C++, and Python, so I cobbled together a simple library from the implementation in https://raw.githubusercontent.com/nplab/DTLS-Examples/master/src/dtls_udp_echo.c.

## Usage
Ensure deps are installed

### Linux
```
apt install openssl libopenssl-dev
```

### Windows (MSYS2)
Windows assumes the usage of msys2, running the **mingw64** terminal.  Otherwise it will not find the OpenSSL libraries.
```
pacman -S openssl openssl-dev
```

### Building
```
mkdir build
cd build
cmake ..
make
```

### Generating certificates
Certificates must be generated and placed in certs (for the time being). See [Stack Overflow](https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl).

```
mkdir build/certs
cd build/certs
openssl req -x509 -nodes -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -sha256 -subj '/CN=localhost'
openssl req -x509 -nodes -newkey rsa:4096 -keyout client-key.pem -out client-cert.pem -sha256 -subj '/CN=localhost'
```
- `-nodes` is NO DES, which means no password protection, remove for passwords
- `-subj` is to automate a dummy CN, so we dont get prompted, seems to not work on msys2

### Issues
- The cookie is just a random number common to library invocation.  I do not know if this is high risk
- This is not implemented or checked against secure coding practices, it may retain information in memory that can leak sensative data
- It accepts all connections (this needs to be fixed by adding the callout for accepting connections, currently accepts everything)
