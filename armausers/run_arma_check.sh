#!/bin/bash
# Script to run the Arma user check tool

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script directory
cd "$SCRIPT_DIR"

# Activate the virtual environment
source venv/bin/activate

# Default values
DAYS=3
USERNAME=$(whoami)
VERBOSE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --days|-d)
            DAYS="$2"
            shift 2
            ;;
        --username|-u)
            USERNAME="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE="--verbose"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --days, -d NUMBER       Number of days to look back (default: 3)"
            echo "  --username, -u NAME     SSH username for arma.vgriz.com (default: current user)"
            echo "  --verbose, -v           Show verbose output"
            echo "  --help, -h              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help to see available options"
            exit 1
            ;;
    esac
done

# Run the Python script with the specified parameters
python3 arma_user_check.py --username "$USERNAME" --sudo-password --days "$DAYS" $VERBOSE

# Deactivate the virtual environment when done
deactivate

echo "Done!"
