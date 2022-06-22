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

## Usage

The command line to run `iothnamed` has the following syntax:
```
iothnamed [OPTIONS] config_file
```

It needs a configuration file (`config file`). The syntax of this configuration file is described
in the following section.

The options of the command are:

* `-d` or `--daemon`: run `iothnamed` as a daemon
* `-p` or `--pidfile`: save the pid of the process in a file

## Configuration file syntax

The configuration file has several sections: stack, dns, auth, static, option

Comments can be inserted using lines beginning by `#`.

### stack section
Following the idea of Internet of Threads it is possible to specify which stacks
are used to provide the service and to forward the requests. Stack specifications are provided
using the syntax of `newstackc` (see [iothconf](https://github.com/virtualsquare/iothconf))

* `stack` the same stack is used to provide the service and to forward the requests
* `rstack` defines the stack to provide the service
* `fstack` defines the stack fo forward the requests

It is not possible to define a stack twice (so either `stack` or at least one of `rstack` `fstack` can be specified.)
A stack definition can be split on several lines. The `stack` and `vnl` options
must appear in the first line.
If a stack definition is omitted the stack provided by the kernel is used.

e.g.:
```
rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=192.168.1.24/24
fstack    stack=kernel
```

This example implements the following configuration.
`iothnamed` runs as a server on the vde network defined by the VNL `vde:///tmp/hub`, the implementation of the stack is
vdestack. Use the kernel stack for all the communication related to forwarded requests to other DNS servers.

### dns section

Set the IP address/addresses of the DNS servers to forward queries when required. Up to three IP addresses can be listed.

e.g.:
```
dns       8.8.8.8
dns       80.80.80.80
dns      2620:119:35::35
```
### net section

This section assign names to ranges of addresses. Up to 64 names can be defined.

e.g.:
```
net       world ::/0
net       local 192.168.1.0/24
net       local 10.0.10.0/24
net       local6 2001:760:2e00:ff00::/64
```

the name `world` matches any IPv6 address. The net name `local` defines the IPv4 addresses 192.168.1.x and 10.0.10.x.
`local6` matches  2001:760:2e00:ff00::/64.

### auth section

This section plays a central role. It defines which services are provided depending on the ip address of the sender who
issues the name resolution request.

* `auth accept`
defines the address ranges allowed to use TCP queries
e.g. only hosts in local (192.168.1.x and 10.0.10.x in the example above) are allowed to send TCP requestsr:
```
          auth      accept local
```

* `auth error`
An error is returned when a query for a specified name/domain is received from an address space.
e.g. queries for the host test.err (no heading dot) and all the hosts/subdomain of .test.err (heading dot)
return an error when the requests come from `local`, 192.168.1.x and 10.0.10.x in the example above.

```
          auth      error local test.err
          auth      error local .test.err
```

* `auth static`
These definitions state who is allowed to query for static addresses. The actual name to address or reverse
mappings are defined in the following `static` section. Here only the access control is defined.
e.g. the following configuration lines permit to retrieve static definitions of hosts in the domain .foo.bar from
any IPv6 address and from IPv4 addresses matching the `local` definition.
Moreover the reverse resolution for addresses in 10.20.30.0/24 and 2001::0/6 is permitted from any IPv6 address.
So queries like 40.30.20.10.inaddr.arpa and .....0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa are permitted.
```
          auth      static local,world .foo.bar
          auth      static world 10.20.30.0/24
          auth      static world 2001::0/64
```

* `auth hash`
Authorize/enable the hash based resolution.
e.g. The following definitions enable the resolution of hosts in the domain .htest.v2.cs.unibo.it using
the base address 2002::1 and hosts in the domain .hash.v2.cs.unibo.it using the base address to be the address
hash.map.v2.cs.unibo.it (in this latter case the actual address is retrieved using a dns query).
```
          auth      hash world .htest.v2.cs.unibo.it 2002::1
          auth      hash world .hash.v2.cs.unibo.it hash.map.v2.cs.unibo.it
```

* `hrev`
Authorize/enable the reverse resolution of hash based addresses.
e.g. The following definitions enable the reverse resolution for the networks of the `auth hash` example.
```
          auth      hrev world 2002::1/64
          auth      hrev world hash.map.v2.cs.unibo.it/64
```

* `otip`
Authorize/enable the one time ip (otip) based resolution. The name resolution changes during the time,
Only legitimate users knowing the password can compute the current address of a server.
e.g. Only local queries can have the current address computed using the password `pwd`:
```
          otip local .otip.v2.cs.unibo.it 2003::1 pwd
```

* `cache`
Define which addresses can retrieve cached record. e.g. queries coming from addresses in `local` can
retieve data for any domain (.):
```
          auth      cache local .
```

* `fwd`
Define which queries can be fowarded depending on the address of the querier:
e.g. queries coming from addresses in `local` can be forwarded.
```
          auth      fwd local .
```

### static section

This section permits to define static mappings.

e.g.:
```
static    A    test.foo.bar 10.20.30.40
static    AAAA test.foo.bar 2001::1
static    PTR  10.20.30.40 test.foo.bar
static    PTR  2001::1 test.foo.bar
static    CNAME  tost.foo.bar test.foo.bar
static    NS  dom.foo.bar dns.foo.bar
static    MX  test.foo.bar 10 mail.foo.bar
static    TXT  test.foo.bar "sempre caro mi fu quest'ermo colle" "long string"
```
Note that PTR records use the convenient numeric address encoding as a shortcut for
names ot the type ....inaddr.arpa or ....ip6.arpa.

### option section

* `option hrevmode` defines the policy to store the reverse mapping for hash resolutions.
There are four supported choices: `always` (the result of any hash resolution is stored for
the later reverse resolution), `net` (store the mapping for queries coming from the same /64
network), `same` (store the mapping ony when the requst comes from the same address, the node
is askign for its own address), `never`.

* `option hashttl` defines the ttl value for hash generated addresses.

* `option tcplistenbacklog` defines the backlog queue length for the tcp connection requests
(it is the argument of listen(2)).

* `option tcptimeout` defines the timeout in seconds to drop idle tcp connections.

## Examples

### static local names + proxy + cache

The following configuration file named `local+forward.rc` sets up the`iothnamed`
dns server to run as a
caching proxy for local clients. The server also defines some local
names for direct and reverse resolution.

```
# The service is provided for queriers reaching this server on the
# vde network vde:///tmp/hub, IP address 192.168.1.24.
rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=192.168.1.24/24
# The kernel stack is used to forward requests to remote dns servers
fstack    stack=kernel

# forward requests using IPv4 packets to 8.8.8.8 or 80.80.80.80
dns       8.8.8.8
dns       80.80.80.80

# the net name 'local' defines the ip range 192.168.1.0/24
net       local 192.168.1.0/24

# clients from 'local' are alloed to send tcp dns requests
auth      accept local
# clients from 'local' can receive replies for names xxxx.test.local
auth      static local .test.local
# clients from 'local' can receive replies for names 1.168.192.in-addr.arpa
auth      static local 192.168.1.0/24
# search in the cache (forwardere query results are cached)
auth      cache local .
# requests from 'local' can be forwarded
auth      fwd local .


# static definitions
static    A one.test.local 192.168.1.1
static    A two.test.local 192.168.1.2
# static definitions for reverse resolution
static    PTR 192.168.1.1 one.test.local 
static    PTR 192.168.1.2 two.test.local 
```

In order to test this configuration start the vde network, e.g.:
```bash
vde_plug null:// hub:///tmp/hub
```

in another terminal window run the iothnamed server:
```bash
iothnamed local+forward.rc
```

in a third terminal window start a vdens and configure it:
```
vdens -R 192.168.1.24 vde:///tmp/hub
ip addr add 192.168.1.1/24 dev vde0
ip link set vde0 up
ip link set lo up
```

Now in the vdens it is possible to query the iothnamed server using
`host` or `dig`. it is also possible to use iothnamed to run network
clients and servers.
```bash
$ host prep.ai.mit.edu
prep.ai.mit.edu is an alias for ftp.gnu.org.
ftp.gnu.org has address 209.51.188.20
ftp.gnu.org has IPv6 address 2001:470:142:3::b
$ ping one.test.local
PING one.test.local (192.168.1.1) 56(84) bytes of data.
64 bytes from one.test.local (192.168.1.1): icmp_seq=1 ttl=64 time=0.038 ms
64 bytes from one.test.local (192.168.1.1): icmp_seq=2 ttl=64 time=0.061 ms
```

### delegated subdomain

In this example the domain dom.v2.cs.unibo.it has been delegated to the
public IP addresses 130.136.31.250 and 2001:760:2e00:ff00::fd

(in order to test this example on your environment, IP addresses and
domain names should be modified to be consistent with your scenario)

Here is the `delegated.rc` configuration file.
```
# the name 'world' matches any IPv6 or IPv4 address.
net       world ::/0

# the static definition for names xxxx.dom,v2,cs,unibo.it
# are available for everybody
auth      static world .dom.v2.cs.unibo.it

static    A one.dom.v2.cs.unibo.it 192.168.1.1
static    AAAA one.dom.v2.cs.unibo.it fc00::1
static    A two.dom.v2.cs.unibo.it 192.168.1.2
static    AAAA two.dom.v2.cs.unibo.it fc00::2
```

Run 	iothnamed` on a host/namespace which owns the IP addresses used
in the subdomain delegation:
```bash
# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: vde0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether f2:09:f8:ff:cb:f4 brd ff:ff:ff:ff:ff:ff
    inet 130.136.31.250/24 scope global vde0
       valid_lft forever preferred_lft forever
    inet6 2001:760:2e00:ff00::fd/64 scope global
       valid_lft forever preferred_lft forever
    inet6 2001:760:2e00:ff00:f009:f8ff:feff:cbf4/64 scope global dynamic mngtmpaddr
       valid_lft 86331sec preferred_lft 14331sec
    inet6 fe80::f009:f8ff:feff:cbf4/64 scope link
       valid_lft forever preferred_lft forever
# ip route
default via 130.136.31.1 dev vde0
130.136.31.0/24 dev vde0 proto kernel scope link src 130.136.31.250
# ip -f inet6 route
2001:760:2e00:ff00::/64 dev vde0 proto kernel metric 256 expires 86397sec pref medium
fe80::/64 dev vde0 proto kernel metric 256 pref medium
default via fe80::2851:20ff:fe4b:b7a5 dev vde0 proto ra metric 1024 expires 297sec hoplimit 64 pref medium
# iothnamed delegated.rc
```

From a random host connected to the Internet:
```
$ host one.dom.v2.cs.unibo.it
one.dom.v2.cs.unibo.it has address 192.168.1.1
one.dom.v2.cs.unibo.it has IPv6 address fc00::1
```

`iothnamed` can also run as a *internet of threads* process (instead
of a real host or a namespace).
Just prepend in the configuration file the definition of rstack:
```
rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=130.136.31.250/24,gw=130.136.31.1
rstack    ip=2001:760:2e00:ff00::fd/64,ip=2001:760:2e00:ff00::ff/64
```

### hash based IPv6 addresses (for local addresses)

Here is the localhash+forward.rc configuration file:
```
rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=192.168.1.24/24
rstack    ip=fc00::24/64
fstack    stack=kernel

dns       8.8.8.8
dns       80.80.80.80

net       local 192.168.1.0/24
net       local fc00::/64
auth      accept local

auth      hash local .hash.local fc00::
auth      hrev local fc00::/64

auth      cache local .
auth      fwd local .

option hrevmode always
```

Start the `iothnamed` server:
```bash
iothnamed localhash+forward.rc
```

Start a vdens and configure it to perform some tests:
```bash
$ vdens -R fc00::24 vde:///tmp/hub
$ ip addr add fc00::1/64 dev vde0
$ ip link set vde0 up
$ ip link set lo up
$ host renzo.hash.local
renzo.hash.local has IPv6 address fc00::4cc:8049:6765:d03a
$ host hic_sunt_leones.hash.local
hic_sunt_leones.hash.local has IPv6 address fc00::9c8f:74b4:705f:6512
$ host fc00::9c8f:74b4:705f:6512
2.1.5.6.f.5.0.7.4.b.4.7.f.8.c.9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa domain name pointer hic_sunt_leones.hash.local.
```

Any name having a `.hash.local` suffix is resolved as a hash based address. In order to define a new network node (host, namespace or process) just decide its name and assign it the correspondent IPv6 hash computed address. The name resolution process will work without any specific configuration.


### hash based IPv6 addresses (with delegation)

The scenario is the combination of the two prvious examples.
In this case the domain hash.v2.cs.unibo.it has been delegated to 2001:760:2e00:ff and 2001:760:2e00:ff, while the reverse resolutionf of 2001:760:2e00:ff00::/64 has been delegated to 2001:760:2e00:ff.

Here is the `delegated+hash.rc` file:
```
net       world ::/0

auth      hash world .hash.v2.cs.unibo.it 2001:760:2e00:ff00::
auth      hrev world 2001:760:2e00:ff00::/64

option hrevmode always

```

Start `iothnamed`:
```
# iothnamed delegated+hash.rc
```

Now from a random host on the internet if is possible to query for any name `something.hash.v2.cs.unibo.it`, e.g.
```bash
$ host renzo.hash.v2.cs.unibo.it
renzo.hash.v2.cs.unibo.it has IPv6 address 2001:760:2e00:ff00:6066:4f84:db3e:c9cb
$ host lucia.hash.v2.cs.unibo.it
lucia.hash.v2.cs.unibo.it has IPv6 address 2001:760:2e00:ff00:cf1:1fe9:aad4:e838
$ host whatever-you-want.hash.v2.cs.unibo.it
whatever-you-want.hash.v2.cs.unibo.it has IPv6 address 2001:760:2e00:ff00:542d:ffcb:17e:8fa7
```

The reverse resolution is also available (provided it queries for an address of a name already queried in the past):

```bash
$ host 2001:760:2e00:ff00:542d:ffcb:17e:8fa7
7.a.f.8.e.7.1.0.b.c.f.f.d.2.4.5.0.0.f.f.0.0.e.2.0.6.7.0.1.0.0.2.ip6.arpa domain name pointer whatever-you-want.hash.v2.cs.unibo.it.
```