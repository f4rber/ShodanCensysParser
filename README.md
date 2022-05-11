# ShodanCensysParser
Script to parse IP from Censys and Shodan API

```
Optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Verbose output
  --search SEARCH, -s SEARCH
                        Search query
  --engine {shodan,censys}, -e {shodan,censys}
                        Engine (shodan or censys)
  --limit LIMIT, -l LIMIT
                        Search limit

python3 sc.py -e censys -l 10 -s "Censys query"

python3 sc.py -e shodan -l 250 -s "Shodan query"
```
