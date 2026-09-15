import os
from datetime import datetime, timezone

from fastapi import FastAPI, Query
from pymongo import MongoClient
from scanner import Scan_Network

app = FastAPI()

# tells app wtd when visiting homepage
@app.get("/")
def home():
    return {"message": "This server is alive"}

@app.get("/scan")
def scan(subnet: str = Query(..., description="IP or subnet to scan")):
    results = Scan_Network(subnet)

    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        saved_to_mongodb = False
    else:
        with MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as client:
            client["SecOps"]["NetworkScans"].insert_one({
                "scan_date": datetime.now(timezone.utc),
                "target_subnet": subnet,
                "results": results,
            })
        saved_to_mongodb = True

    return {
        "subnet": subnet,
        "results": results or [],
        "saved_to_mongodb": saved_to_mongodb,
    }