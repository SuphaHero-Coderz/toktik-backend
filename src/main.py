from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import NoCredentialsError

app = FastAPI()

load_dotenv()

s3 = boto3.client('s3', 
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY"),
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
)

origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/generate_presigned_url/{object_key}")
async def generate_presigned_url(object_key: str):
    try:
        # Generate a presigned URL for the S3 object
        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': os.getenv("BUCKET_NAME"),
                'Key': object_key,
            },
            ExpiresIn=3600  # The URL will expire in 1 hour
        )

        return {"presigned_url": presigned_url}

    except NoCredentialsError:
        return {"error": "AWS credentials not available."}

