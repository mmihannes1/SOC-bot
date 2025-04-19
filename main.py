import argparse
import log_parser


def main():
    parser = argparse.ArgumentParser(
        description="A Mini-SOC Bot. Parses Zeeks .log files and extracts information."
    )
    parser.add_argument("logfile", help="Path to the Zeek log file to be parsed.")
    args = parser.parse_args()

    if args.logfile:
        print(f"Parsing log file: {args.logfile}")

        dns_log = log_parser.parse_dns_log(args.logfile)

        print(dns_log)


if __name__ == "__main__":
    main()
