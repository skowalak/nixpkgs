import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Script to handle Azure CLI extensions")
    parser.add_argument('--cli-version', required=True, type=str, help="version of azure-cli (required)")
    parser.add_argument('--extension', type=str, help="name of extension to query")
    parser.add_argument('--cache-dir', type=str, help="path where to cache the extension index")
    parser.add_argument('--requirements', type=str, choices=['true', 'false'], help="filter for extensions with/without requirements")
    args = parser.parse_args()

    if args.cli_version:
        print(f"Azure CLI Version: {args.cli_version}")

    if args.extension:
        print(f"Querying extension: {args.extension}")

    if args.file:
        print(f"Using file: {args.file}")

    if args.download:
        print("Downloading extension index file...")

    if args.requirements:
        if args.requirements.lower() == 'true':
            print("Filtering extensions with requirements...")
        else:
            print("Filtering extensions without requirements...")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments provided, show usage
        print("Usage:")
        print("  --cli-version=<version>      version of azure-cli (required)")
        print("  --extension=<name>           name of extension to query")
        print("  --file=<path>                path to extension index file")
        print("  --download                   download extension index file")
        print("  --nix                        output Nix expression")
        print("  --requirements=<true/false>  filter for extensions with/without requirements")
    else:
        main()
