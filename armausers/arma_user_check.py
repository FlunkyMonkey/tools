#!/usr/bin/env python3
"""
Arma User Check - A tool to check user connections on arma.vgriz.com
This script connects to the arma.vgriz.com server, runs a journalctl command
to extract user connection information, and formats it in a readable way.
"""

import paramiko
import re
import sys
import os
import getpass
import argparse
from datetime import datetime
import pytz

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Check Arma user connections')
    parser.add_argument('--host', default='arma.vgriz.com', help='SSH host to connect to')
    parser.add_argument('--username', help='SSH username')
    parser.add_argument('--key-file', help='SSH private key file path')
    parser.add_argument('--password', action='store_true', help='Prompt for password instead of using key file')
    parser.add_argument('--sudo-password', action='store_true', help='Prompt for sudo password')
    parser.add_argument('--days', type=int, default=1, help='Number of days to look back in the logs')
    parser.add_argument('--test-connection', action='store_true', help='Test SSH connection only without running commands')
    parser.add_argument('--verbose', action='store_true', help='Show verbose output for debugging')
    return parser.parse_args()

def convert_to_pst(date_str, time_str):
    """Convert UTC time to PST (non-military format)."""
    # Parse the date and time
    dt_str = f"{date_str} {time_str}"
    dt = datetime.strptime(dt_str, "%b %d %H:%M:%S")
    
    # Set the year (journalctl doesn't include year)
    current_year = datetime.now().year
    dt = dt.replace(year=current_year)
    
    # Assume the time is in UTC and convert to PST
    utc = pytz.timezone('UTC')
    pst = pytz.timezone('America/Los_Angeles')
    
    dt_utc = utc.localize(dt)
    dt_pst = dt_utc.astimezone(pst)
    
    # Format in non-military time
    return dt_pst.strftime("%b %d %I:%M:%S %p")

def extract_user_info(log_line):
    """Extract user connection information from a log line."""
    # Regular expression to match the log line format
    # This pattern captures the username until a comma or end of line
    pattern = r'(\w+\s+\d+)\s+(\d+:\d+:\d+).*Name=([^,]+)(?:,|$)'
    match = re.search(pattern, log_line)
    
    if match:
        date, time, username = match.groups()
        # Trim any trailing whitespace from the username
        username = username.strip()
        pst_datetime = convert_to_pst(date, time)
        return {
            'datetime': pst_datetime,
            'username': username
        }
    return None

def test_connection(ssh_client, verbose=False):
    """Test the SSH connection by running a simple command."""
    if verbose:
        print("Testing connection with 'whoami' command...")
    
    stdin, stdout, stderr = ssh_client.exec_command("whoami")
    output = stdout.read().decode('utf-8').strip()
    error = stderr.read().decode('utf-8')
    
    if error:
        print(f"Error testing connection: {error}")
        return False
    
    if verbose:
        print(f"Connection successful. Logged in as: {output}")
    return True

def test_sudo_access(ssh_client, sudo_password=None, verbose=False):
    """Test if the user has sudo access."""
    if verbose:
        print("Testing sudo access...")
    
    if sudo_password:
        command = f"echo '{sudo_password}' | sudo -S -l"
    else:
        command = "sudo -n -l"
    
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    if 'password is required' in error or 'a password is required' in error:
        if verbose:
            print("Sudo access requires a password")
        return False
    elif error and 'not allowed to execute' in error:
        if verbose:
            print("User does not have sudo access")
        return False
    elif output and ('ALL' in output or 'journalctl' in output):
        if verbose:
            print("User has sudo access")
        return True
    else:
        if verbose:
            print(f"Unexpected response when testing sudo access: {output}\nError: {error}")
        return False

def run_remote_command(ssh_client, days=1, sudo_password=None, verbose=False):
    """Run the journalctl command on the remote server."""
    # First try a simpler approach - maybe journalctl doesn't need sudo for this user
    if verbose:
        print("Trying journalctl command without sudo first...")
    
    simple_command = f"journalctl -u arma-reforger.service --since '{days} days ago' | grep -E 'Name='"
    stdin, stdout, stderr = ssh_client.exec_command(simple_command)
    simple_output = stdout.readlines()
    simple_error = stderr.read().decode('utf-8')
    
    if simple_output and not simple_error:
        if verbose:
            print("Successfully ran journalctl without sudo")
        return simple_output
    
    if verbose:
        if simple_error:
            print(f"Error running without sudo: {simple_error}")
        print("Trying with sudo...")
    
    # Construct the command with the specified number of days
    if sudo_password:
        # Use echo to pipe the password to sudo -S
        command = f"echo '{sudo_password}' | sudo -S journalctl -u arma-reforger.service --since '{days} days ago' | grep -E 'Name='"
    else:
        # Try without password in case sudo is configured with NOPASSWD
        command = f"sudo journalctl -u arma-reforger.service --since '{days} days ago' | grep -E 'Name='"
    
    stdin, stdout, stderr = ssh_client.exec_command(command)
    
    # Check for errors
    error = stderr.read().decode('utf-8')
    output = stdout.readlines()
    
    if error and ('password' in error.lower() or 'a terminal is required' in error.lower()):
        if not sudo_password:
            print("Sudo requires a password. Please run with --sudo-password option.")
        else:
            print("Incorrect sudo password provided.")
        if verbose:
            print(f"Full error: {error}")
        return []
    elif error and 'command not found' in error.lower():
        print("journalctl command not found on the server. Is this an Ubuntu system?")
        if verbose:
            print(f"Full error: {error}")
        return []
    elif error and not any(output):
        print(f"Error executing remote command: {error}")
        return []
    elif not any(output):
        if verbose:
            print("Command executed successfully but returned no results")
        return []
    
    if verbose:
        print(f"Command executed successfully, found {len(output)} matching lines")
    return output

def connect_to_server(host, username, key_file=None, password=None, verbose=False):
    """Connect to the remote server using SSH."""
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if verbose:
            print(f"Attempting to connect to {username}@{host}...")
            
        if password:
            if verbose:
                print("Using password authentication")
            ssh_client.connect(host, username=username, password=password)
        elif key_file:
            if verbose:
                print(f"Using key file: {key_file}")
            ssh_client.connect(host, username=username, key_filename=key_file)
        else:
            # Try to use the default key in ~/.ssh/id_rsa
            default_key = os.path.expanduser('~/.ssh/id_rsa')
            if os.path.exists(default_key):
                if verbose:
                    print(f"Using default key: {default_key}")
                ssh_client.connect(host, username=username, key_filename=default_key)
            else:
                if verbose:
                    print("No key file found, falling back to password authentication")
                password = getpass.getpass(f"No key file provided. Enter password for {username}@{host}: ")
                ssh_client.connect(host, username=username, password=password)
        
        if verbose:
            print(f"Successfully connected to {username}@{host}")
            
        return ssh_client
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {username}@{host}. Please check your credentials.")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"SSH error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to connect to {host}: {str(e)}")
        sys.exit(1)

def main():
    args = parse_args()
    verbose = args.verbose
    
    # Get username if not provided
    username = args.username
    if not username:
        username = input(f"Enter username for {args.host}: ")
    
    # Get SSH password or use key
    if args.password:
        password = getpass.getpass(f"Enter password for {username}@{args.host}: ")
        ssh_client = connect_to_server(args.host, username, password=password, verbose=verbose)
    else:
        ssh_client = connect_to_server(args.host, username, key_file=args.key_file, verbose=verbose)
    
    try:
        # Just test the connection if requested
        if args.test_connection:
            if test_connection(ssh_client, verbose):
                print(f"Successfully connected to {username}@{args.host}")
                has_sudo = test_sudo_access(ssh_client, None, verbose)
                if not has_sudo:
                    print("User does not have passwordless sudo access. You'll need to use --sudo-password.")
                    if args.sudo_password or input("Test with sudo password? (y/n): ").lower() == 'y':
                        sudo_password = getpass.getpass(f"Enter sudo password for {username}@{args.host}: ")
                        has_sudo = test_sudo_access(ssh_client, sudo_password, verbose)
                        if has_sudo:
                            print("Sudo access confirmed with password.")
                        else:
                            print("Failed to get sudo access even with password.")
                else:
                    print("User has passwordless sudo access.")
            return
        
        # Get sudo password if needed
        sudo_password = None
        if args.sudo_password:
            sudo_password = getpass.getpass(f"Enter sudo password for {username}@{args.host}: ")
        
        # Run the command and get the output
        print(f"Fetching Arma user connections from the last {args.days} day(s)...")
        log_lines = run_remote_command(ssh_client, args.days, sudo_password, verbose)
        
        # If no results and no sudo password was provided, try prompting for it
        if not log_lines and not sudo_password:
            print("No results found. Trying again with sudo password...")
            sudo_password = getpass.getpass(f"Enter sudo password for {username}@{args.host}: ")
            log_lines = run_remote_command(ssh_client, args.days, sudo_password, verbose)
        
        # Process and display the results
        connections = []
        for line in log_lines:
            user_info = extract_user_info(line.strip())
            if user_info and user_info not in connections:
                connections.append(user_info)
        
        if connections:
            print("\nArma User Connections (PST):")
            print("=" * 50)
            for conn in connections:
                print(f"{conn['datetime']} - {conn['username']}")
            print("=" * 50)
            print(f"Total unique connections: {len(connections)}")
        else:
            print("No user connections found in the specified time period.")
            if verbose:
                print("This could be because:")
                print("1. There were no connections in the specified time period")
                print("2. The log format is different than expected")
                print("3. The service name 'arma-reforger.service' is incorrect")
                print("4. You don't have permission to access the logs")
    
    finally:
        ssh_client.close()

if __name__ == "__main__":
    main()
