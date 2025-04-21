import argparse
import log_parser
import rule_engine


def main():
    parser = argparse.ArgumentParser(
        description="A Mini-SOC Bot. Parses Zeeks .log files."
    )
    parser.add_argument("-dns ", "--dns", help="Parse DNS log.")
    parser.add_argument("-http", "--http", help="Parse HTTP log.")
    parser.add_argument("-conn", "--conn", help="Parse connection log.")
    args = parser.parse_args()

    if args.dns:
        print(f"Parsing log file: {args.dns}")
        dns_log = log_parser.parse_dns_log(args.dns)
        print(dns_log)

    if args.http:
        print(f"Parsing log file: {args.http}")
        http_log = log_parser.parse_http_log(args.http)
        rule = rule_engine.load_rule("rules/http/exfiltration_over_http.json")
        matches = rule_engine.apply_rule(http_log, rule)
        print(f"Matches: {matches}")

        # print(http_log)

    if args.conn:
        print(f"Parsing log file: {args.conn}")
        conn_log = log_parser.parse_conn_log(args.conn)
        print(conn_log)


if __name__ == "__main__":
    main()
