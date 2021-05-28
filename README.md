
# DNS Goisoner :vomiting_face:

An on-path DNS poisoning attack tool, written in Golang. 

Developed using the GoPacket library, supports just plain (UDP) DNS
traffic over port 53.

DNS Goisoner captures the traffic from a network interface in promiscuous mode, and injects forged
responses to selected DNS A requests with the goal of poisoning the cache of
the victim's resolver.
## Parameters & Usage 💬

DNS Goisoner has three parameters and usage for this:
```
go run dnspoison.go [-i interface] [-f hostnames] [expression]
```

- **-i :** Listen on network device <interface> (e.g., eth0). If not specifed, default interface (eth0) will be used.
- **-f :** Read a list of IP adress and hostname pairs specifying the hostnames to be hijacked. If '-f' is not specified, DNS Goisoner will forge replies to all observed requests with the chosen interface's IP address as an answer.
- **<expression> :** It is an optional argument. It is a BPF filter that specifies a subset of the traffic to be monitored. This option is useful for targeting a single victim or a group of victims.


## Example Hostnames & Usages

Hostnames file should contain one IP and hostname pair per line, seperated by whitespace, in the following format:
```
100.90.80.70      ex.example.com
10.9.8.7          amp.example.com
192.168.62.27     le.example.com
```

Example usages:

```bash
sudo go run main.go -i ens33 -f targets.txt

sudo go run main.go -i ens33

sudo go run main.go -i wlan0 -f targets.txt "dst host 192.168.2.10"
```

## Disclaimer ⛔

All information and software available on this page are for educational and test purposes only. Use these at your own discretion, the repository owners cannot be held responsible for any damages caused.

Usage of all tools on this repository for attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws. We assume no liability and are not responsible for any misuse or damage caused by this repository.
