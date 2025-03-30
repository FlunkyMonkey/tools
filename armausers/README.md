# Arma User Check

A Python tool to check user connections on the Arma Reforger server.

## Description

This script connects to the arma.vgriz.com server, runs a journalctl command to extract user connection information, and formats it in a readable way showing:
- Connection date
- Connection time (in PST, non-military format)
- Steam username

## Requirements

- Python 3.6+
- Dependencies listed in `requirements.txt`

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Make the script executable:

```bash
chmod +x arma_user_check.py
```

## Usage

Basic usage:

```bash
./arma_user_check.py
```

This will prompt you for a username to connect to arma.vgriz.com.

### Command Line Options

- `--host`: SSH host to connect to (default: arma.vgriz.com)
- `--username`: SSH username
- `--key-file`: SSH private key file path
- `--password`: Prompt for password instead of using key file
- `--days`: Number of days to look back in the logs (default: 1)

### Examples

Check connections from the last 3 days:

```bash
./arma_user_check.py --days 3
```

Specify a username:

```bash
./arma_user_check.py --username your_username
```

Use a specific SSH key:

```bash
./arma_user_check.py --key-file ~/.ssh/id_rsa_custom
```

## SSH Setup

To connect to the server without entering a password each time:

1. Generate an SSH key pair if you don't have one:
   ```bash
   ssh-keygen -t rsa -b 4096
   ```

2. Copy your public key to the server:
   ```bash
   ssh-copy-id your_username@arma.vgriz.com
   ```

3. If you're connecting for the first time, you'll need to accept the host key.

## Notes

- You need sudo access on the remote server to run the journalctl command
- The script assumes the server logs are in UTC and converts them to PST
