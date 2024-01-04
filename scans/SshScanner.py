import re

import nmap

from config import Config


class SshScanner:
    @staticmethod
    def scan(target: str, port: int = 22) -> dict:
        def parse_script_output(input_list: list[str]) -> dict[str, list[str]]:
            config_dict = {}
            current_key = ""

            for line in input_list:
                # Match lines with key and value pairs
                match = re.match(r"\s*([\w_]+):\s*\((\d+)\)", line)
                if match:
                    current_key = match.group(1)
                    config_dict[current_key] = []
                    continue

                # Match lines with values (ignore empty lines)
                match = re.match(r"\s+(\S+)", line)
                if match and current_key:
                    config_dict[current_key].append(match.group(1))

            return config_dict

        def check_unsafe_algorithms(algorithms: dict[str, list[str]]):
            found_unsafe_algos = {
                key: list(set(values) & set(Config.unsafe_ssh_algorithms[key]))
                for key, values in algorithms.items()
                if key in Config.unsafe_ssh_algorithms
            }

            return found_unsafe_algos

        algos = {}

        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, arguments=f"--script ssh2-enum-algos -sV -p {port}")

            first_host = scanner.all_hosts()[0]

            if "tcp" not in scanner[first_host] or port not in scanner[first_host]["tcp"]:
                return {}

            script_output = scanner[first_host]["tcp"][port].get("script", {}).get("ssh2-enum-algos", "").split("\n")

            algos = parse_script_output(script_output)

        except KeyError as e:
            print(f"KeyError: {e}")

        return check_unsafe_algorithms(algos)
