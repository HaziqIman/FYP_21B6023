import win32pdh
import sys
import subprocess


hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

def run_as_admin():
    """
    Re-run the script with elevated privileges.
    Note: If your entire Flask app is already running as admin,
    you can omit or modify this to suit your needs.
    """
    print("Re-running with elevated privileges...")
    try:
        subprocess.run(
            [
                "powershell",
                "Start-Process",
                "python",
                f'"{sys.argv[0]}"',
                "-Verb",
                "RunAs"
            ],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
    sys.exit()

def block_url(url, is_admin_func):
    """
    Appends a block entry (0.0.0.0) to the Windows hosts file to block a given URL.
    """
    
    if not is_admin_func():
        print("This script needs to be run as Administrator. Re-running with elevated privileges...")
        run_as_admin()
        return

    try:
        with open(hosts_path, "a") as hosts_file:
            hosts_file.write(f"127.0.0.1 {url}\n")
        print(f"Successfully blocked {url}")
    except Exception as e:
        print(f"Error blocking URL {url}: {e}")

def unblock_url(url, is_admin_func):
    """
    Removes any block entries for the given URL from the Windows hosts file.
    """
    if not is_admin_func():
        print("This script needs to be run as Administrator. Re-running with elevated privileges...")
        run_as_admin()
        return

    try:
        with open(hosts_path, "r") as hosts_file:
            lines = hosts_file.readlines()

        with open(hosts_path, "w") as hosts_file:
            for line in lines:
                if url not in line:
                    hosts_file.write(line)
                else:
                    print(f"Unblocked {url}")

    except Exception as e:
        print(f"Error unblocking URL {url}: {e}")


