
import subprocess
import json

def get_firewall_policies():
    try:
        # Run netsh to get firewall rules
        command = "netsh advfirewall firewall show rule name=all"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            raise Exception(result.stderr)

        # Parse netsh output
        raw_output = result.stdout.splitlines()
        policies = []
        current_policy = {}

        for line in raw_output:
            line = line.strip()
            if line.startswith("Rule Name:"):
                # Save the previous policy and start a new one
                if current_policy:
                    policies.append(current_policy)
                current_policy = {"RuleName": line.split(": ", 1)[1]}
            elif line.startswith("Enabled:"):
                current_policy["Enabled"] = line.split(": ", 1)[1]
            elif line.startswith("Direction:"):
                current_policy["Direction"] = line.split(": ", 1)[1]
            elif line.startswith("LocalIP:"):
                current_policy["LocalIP"] = line.split(": ", 1)[1]
            elif line.startswith("RemoteIP:"):
                current_policy["RemoteIP"] = line.split(": ", 1)[1]
            elif line.startswith("Action:"):
                current_policy["Action"] = line.split(": ", 1)[1]
            elif line.startswith("Protocol:"):
                current_policy["Protocol"] = line.split(": ", 1)[1]
            elif line.startswith("LocalPort:"):
                current_policy["LocalPort"] = line.split(": ", 1)[1]

        # Add the last policy
        if current_policy:
            policies.append(current_policy)

        return policies

    except Exception as e:
        return {"error": str(e)}
    

def add_firewall_policy(data):
    try:
        # Ensure action is correctly mapped: "Deny" should be "Block"
        action_mapping = {
            "Allow": "allow",
            "Deny": "block"
        }
        action = action_mapping.get(data["action"], "allow")  # Default to allow

        # Fix direction mapping
        direction_mapping = {
            "Inbound": "in",
            "Outbound": "out"
        }
        direction = direction_mapping.get(data["direction"], "in")  # Default to in

        # Default to 'any' if no IP is provided
        local_ip = data.get("source_ip", "any")  # Maps to LocalIP
        remote_ip = data.get("destination_ip", "any")  # Maps to RemoteIP

        # Convert protocol to uppercase for consistency
        protocol = data['protocol'].upper()

        # Construct the base command
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f'name="{data["rule_name"]}"',  # Ensures the name is quoted
            f"dir={direction}",
            f"action={action}",
            f"protocol={protocol}",
            f"localip={local_ip}",
            f"remoteip={remote_ip}",
            "enable=yes"
        ]

        # If the protocol is not ICMP, include ports
        if protocol != "ICMPV4" and protocol != "ICMPV6":
            command.extend([
                f"localport={data['port']}",
                "remoteport=any"  # Fix for TCP/UDP
            ])

        # Debug: Print the command before execution
        print("Executing command:", " ".join(command))

        # Execute the command and capture output
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        # Debug: Log command output
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

        # Check if command execution was successful
        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "message": result.stderr}

    except Exception as e:
        return {"success": False, "message": str(e)}




def disable_firewall_policy(rule_name):
    """
    Disables an existing firewall policy by name.
    """
    rule_name_stripped = rule_name.strip()
    try:
        command = f'netsh advfirewall firewall set rule name="{rule_name_stripped}" new enable=no'

        print("Executing command:", " ".join(command))
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "message": result.stderr}
    except Exception as e:
        return {"success": False, "message": str(e)}


def delete_firewall_policy(rule_name):
    """
    Deletes an existing firewall policy by name.
    """
    rule_name_stripped = rule_name.strip()
    try:
        command = f'netsh advfirewall firewall delete rule name="{rule_name_stripped}"'
        print("Executing command:", " ".join(command))
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "message": result.stderr}
    except Exception as e:
        return {"success": False, "message": str(e)}