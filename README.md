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

It is not possible to define a stack twice (so either `stack` or at least one of `rstack` `fstack` can be specified.
If a stack definition is omitted the stack provided by the kernel is used.

e.g.:
```
rstack     stack=vdestack,vnl=vde:///tmp/hub,eth,ip=192.168.1.24/24,mac=80:01:01:01:01:01
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
