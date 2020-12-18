# Network Analyzer

This project is a network analyzer.

## How to use it

To launch the program, you can type the commands:

```bash
make
./bin/main: -i <interface> -v <int> -o <offline file> (-f <filter>)
```

Notice that the `-o` is optional. If you launch the program with invalid arguments or with an invalid interface, the help will be printed out (with the list of valid interfaces).

You can also use `make run FILE=name_of_the_file` to launch the offline mode in verbose 3. 

## Supported packet

- ARP
- BOOTP
- DNS
- ETHERNET
- FTP
- HTTP
- ICMP
- ICMPv6
- IMAP
- IPv4
- IPv6
- POP
- RARP
- SCTP

## Informations

When I defined a structure, `__attribute__((packed))` was used to tell the compiler to not add padding in it.


## Contributors
- Thomas Rives
