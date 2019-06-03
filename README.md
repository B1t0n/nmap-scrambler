# Nmap-Scrambler

This tool scrambles one extensive Nmap command into multiple nmap commands in preparation to use with Distributed Nmap scan.
It also randomize the targeted IP addresses and ports.

Tested on Kali linux.

## Requirements

Built-in Nmap 7.70+

## Usage

```md
nmap-scrambler.py [-h] -i INPUT -o OUTPUT -n IPCOUNT -p PORTCOUNT

Scramble Nmap command IP and ports into multiple nmap command in prepartinon
to use with DNmap

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        FILE CONTAINNING ONE NMAP COMMAND with all flags,IPs
                        and ports to be scanned (TCP scan only)
  -o OUTPUT, --output OUTPUT
                        Output filename where the list of scrambled nmap
                        commands will be wrritten
  -n IPCOUNT, --ipcount IPCOUNT
                        Number of IP addresses per generated nmap command
  -p PORTCOUNT, --portcount PORTCOUNT
                        Number of ports per generated nmap command

Example: python nmap-scrambler.py -i <FILE CONTAINNING NMAP COMMAND> -o <NMAP_COMMANDS.lst> -n <NUMBER OF IPs per command> -p <NUMBER of ports per command>

```
