import sys
import os

# Ensure src is in the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from gui import main
except ImportError as e:
    print(f"Error: Could not find GUI module. {e}")
    print("Please ensure you have installed the requirements: pip install -r requirements.txt")
    sys.exit(1)

if __name__ == "__main__":
    main()
