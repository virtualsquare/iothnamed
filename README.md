# iothnamed:
### a DNS server/forwarder/cache for the Internet of Threads

`iothnamed` is a DNS server/forwarder/cache for the Internet of Threads supporting
hash based IPv6 addresses and OTIP, i.e. one time IP.

## How to install `iothnamed`

### Pre-requisites:
`iothnamed` depends on the following libraries, that must be installed in advance:

* ioth
* iothdns
* iothconf
* iothaddr
* stropt

`iothnamed` uses the cmake building system.
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```
