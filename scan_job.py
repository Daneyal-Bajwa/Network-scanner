import os

from main import save_scan
from scanner import Get_Local_Subnet, Scan_Network


def run() -> None:
    subnet = os.getenv("TARGET_SUBNET") or Get_Local_Subnet()
    results = Scan_Network(subnet) or []
    if not save_scan(subnet, results):
        raise RuntimeError("MONGO_URI is required for scheduled scans")
    print(f"Saved scan for {subnet} to MongoDB")


if __name__ == "__main__":
    run()
