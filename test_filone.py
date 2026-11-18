
import os
import boto3
from dotenv import load_dotenv
from botocore.config import Config

load_dotenv()

client = boto3.client(
    "s3",
    endpoint_url=f"https://s3.{os.getenv('FIL_REGION')}.filonecontent.com",
    aws_access_key_id=os.getenv("FIL_ACCESS_KEY"),
    aws_secret_access_key=os.getenv("FIL_SECRET_KEY"),
    region_name=os.getenv("FIL_REGION"),
    config=Config(s3={"addressing_style": "path"})
)

bucket = os.getenv("FIL_BUCKET")

try:
    client.head_bucket(Bucket=bucket)
    print("SUCCESS: Fil One connected!")
    print("Bucket:", bucket)
except Exception as error:
    print("CONNECTION FAILED")
    print(type(error).__name__)
    print(error)
