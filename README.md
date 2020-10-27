# Network Analyzer

## How to use it

To launch the program, you can type the commands:

```bash
make
./bin/main: -i <interface> -v <int> -o <offline file> (-f <filter>)
```

Notice that the `-o` is optional. If you launch the program with invalid arguments or with an invalid interface, the help will be printed out (with the list of valid interfaces).

## Supported packet

## Things to not forget

DHCP: magic-cookie `0x6382 5363`

## Contributors
- Thomas Rives
