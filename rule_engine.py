import json


def load_rule(rule_path):
    with open(rule_path, "r") as f:
        return json.load(f)


def match_rule(entry, rule):
    for cond in rule.get("conditions", []):
        field = cond["field"]
        value = entry.get(field)

        if "equals" in cond:
            if value != cond["equals"]:
                return False
        if "greater_than" in cond:
            try:
                if float(value) <= cond["greater_than"]:
                    return False
            except (ValueError, TypeError):
                return False
    return True


def apply_rule(log_entries, rule):
    return [entry for entry in log_entries if match_rule(entry, rule)]
