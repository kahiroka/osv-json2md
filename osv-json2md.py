import sys
import json
from pathlib import Path

def gen_report_with_cwe(file):
    with open(file, "r") as f:
        print(f"# {file}")
        print("| OSV URL | CVSS | CWE | ECOSYSTEM | PACKAGE | VERSION | FIXED VERSION | SOURCE |")
        print("|---------|------|-----|-----------|---------|---------|---------------|--------|")
        jj = json.load(f)

        for result in jj["results"]:
            src_path = result["source"]["path"]

            for package in result["packages"]:
                name = package["package"]["name"]
                version = package["package"]["version"]
                ecosystem = package["package"]["ecosystem"]
                cwes = []
                fixed = []
                for vuln in package["vulnerabilities"]:
                    # cwe
                    if "database_specific" in vuln:
                        # crates
                        if not "cwe_ids" in vuln["database_specific"]:
                            break
                        ids = vuln["database_specific"]["cwe_ids"]
                        cwes.append([])
                        for i in ids:
                            if i in ["CWE-506", "CWE-508", "CWE-509"]: # malicious code
                                cwes[-1].append(f"**{i}**")
                            else:
                                cwes[-1].append(i)
                    else:
                        cwes.append([])

                    # fixed version
                    if "affected" in vuln:
                        fixed.append([])
                        for affected in vuln["affected"]:
                            if "ranges" in affected:
                                for rang in affected["ranges"]:
                                    rtype = ["ECOSYSTEM", "SEMVER", "GIT"]
                                    if "type" in rang and rang["type"] in rtype:
                                        frm = "?"
                                        for event in rang["events"]:
                                            if "introduced" in event:
                                                frm = event["introduced"]
                                            elif "fixed" in event:
                                                fixed[-1].append(event["fixed"])

                n = 0
                for group in package["groups"]:
                    severity = group["max_severity"]
                    if severity != "":
                        if float(severity) < 7.0:
                            break
                        if float(severity) >= 9.0:
                            severity = f"**{severity}**"

                    for i in group["ids"]:
                        ids = "https://osv.dev/" + i
                        if len(cwes) > 0:
                            cwes_str = ", ".join(list(set(cwes[n])))
                        else:
                            cwes_str = ""

                        if len(fixed) > 0:
                            fixed_str = ", ".join(list(set(fixed[n])))
                        else:
                            fixed_str = ""
                        n += 1
                        print(f"|{ids}|{severity}|{cwes_str}|{ecosystem}|{name}|{version}|{fixed_str}|{src_path}|")
                        #severity = ""

def main():
    if len(sys.argv) != 2:
        print(f"{sys.argv[0]} osv.json")
        sys.exit(1)

    for p in Path(sys.argv[1]).glob("*.json"):
            gen_report_with_cwe(p)

if __name__ == "__main__":
    main()
