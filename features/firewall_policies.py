
import subprocess
import json

def get_firewall_policies():
    try:
        
        command = "netsh advfirewall firewall show rule name=all"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            raise Exception(result.stderr)

        
        raw_output = result.stdout.splitlines()
        policies = []
        current_policy = {}

        for line in raw_output:
            line = line.strip()
            if line.startswith("Rule Name:"):
                
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

        
        if current_policy:
            policies.append(current_policy)

        return policies

    except Exception as e:
        return {"error": str(e)}
    

def add_firewall_policy(data):
    try:
        
        action_mapping = {
            "Allow": "allow",
            "Deny": "block"
        }
        action = action_mapping.get(data["action"], "allow")  

        
        direction_mapping = {
            "Inbound": "in",
            "Outbound": "out"
        }
        direction = direction_mapping.get(data["direction"], "in")  

        
        local_ip = data.get("source_ip", "any")  
        remote_ip = data.get("destination_ip", "any")  

        
        protocol = data['protocol'].upper()

        
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f'name="{data["rule_name"]}"',  
            f"dir={direction}",
            f"action={action}",
            f"protocol={protocol}",
            f"localip={local_ip}",
            f"remoteip={remote_ip}",
            "enable=yes"
        ]

        
        if protocol != "ICMPV4" and protocol != "ICMPV6":
            command.extend([
                f"localport={data['port']}",
                "remoteport=any"  
            ])

        
        print("Executing command:", " ".join(command))

        
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

        
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