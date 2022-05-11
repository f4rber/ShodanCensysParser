import json
import shodan
import argparse
from censys.search import CensysHosts

parser = argparse.ArgumentParser(description="Shodan&Censys parser")
parser.add_argument('--verbose', '-v', help='Verbose output', action="store_true")
parser.add_argument('--search', '-s', type=str, help='Search query', required=True)
parser.add_argument('--engine', '-e', choices=['shodan', 'censys'], help='Engine (shodan or censys)', required=True)
parser.add_argument('--limit', '-l', type=int, help='Search limit', default=100)
args = parser.parse_args()

shodan_api = shodan.Shodan("")
censys_api_key = ""
censys_api_secret = ""
clean_result = []


def shodan_search(query, limit=args.limit):
    try:
        results = shodan_api.search(query, limit=limit)
        print(f"Results found: {results['total']}")
        for result in results['matches']:
            keys = result.keys()
            if result["ip_str"] not in clean_result:
                print(result["ip_str"])
                if args.verbose:
                    # print(result["data"])
                    # print(results['matches'])
                    if "ssl" in keys:
                        print(json.loads(json.dumps(result["ssl"], indent=4))["cert"]["subject"])
                    if "hostnames" in keys:
                        print(result["hostnames"])
                    if "cpe" in keys:
                        print(result["cpe"])
                    if "cpe23" in keys:
                        print(result["cpe23"])
                    print("")
                clean_result.append(result["ip_str"])
        print(f"\n\nResults parsed (duplicates removed): {len(clean_result)}")
    except shodan.APIError as e:
        print(f'Error: {str(e)}')


def censys_search(dork, limit=args.limit):
    try:
        h = CensysHosts(api_id=censys_api_key, api_secret=censys_api_secret)
        # print(h.quota())
        results = h.search(query=dork, per_page=100, pages=limit)
        
        for result in results:
            for rr in result:
                res = json.dumps(rr, indent=4)
                r = json.loads(res)
                if r["ip"] not in clean_result:
                    clean_result.append(r["ip"])
                    print(r["ip"])
                    if args.verbose:
                        for service in r["services"]:
                            print(str(service["port"]) + ":" + str(service["service_name"]))
                        print("")
        print(f"\n\nResults parsed (duplicates removed): {len(clean_result)}")
    except Exception as error:
        print('[!] Error: ' + str(error))


if __name__ == "__main__":
    print(f"Search query: {args.search}")
    if args.engine == "shodan":
        shodan_search(args.search)
    elif args.engine == "censys":
        censys_search(args.search)
    else:
        print("Error!")
        exit(1)
    print("Done!")
