# Network Analyzer

TODO: Clean up ICMP and ICMPv6 because switches are TOO HUGE.

## How to use it

To launch the program, you can type the commands:

```bash
make
./bin/main: -i <interface> -v <int> -o <offline file> (-f <filter>)
```

Notice that the `-o` is optional. If you launch the program with invalid arguments or with an invalid interface, the help will be printed out (with the list of valid interfaces).

## Supported packet

## Header done
- Ethernet
- IPv4
- IPv6

## Things to not forget

DHCP: magic-cookie `0x6382 5363`

## Ideas

When 0.0.0.0 print unknown ?

## Contributors
- Thomas Rives
