import os

import boto3
from botocore.exceptions import NoCredentialsError
from dotenv import load_dotenv
from fastapi import APIRouter

router = APIRouter(tags=["s3"])

load_dotenv()

s3 = boto3.client('s3',
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY"),
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
)
@router.get("/generate_presigned_url/{object_key}")
async def generate_presigned_url(object_key: str):
    """
    Generates a presigned URL for upload to S3
    """
    try:
        # Generate a presigned URL for the S3 object
        presigned_url = s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': os.getenv("BUCKET_NAME"),
                'Key': object_key,
                'ContentType': 'video/*'
            },
            ExpiresIn=3600,
            HttpMethod="PUT"
        )

        return {"presigned_url": presigned_url}

    except NoCredentialsError:
        return {"error": "AWS credentials not available."}
