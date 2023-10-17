import json
import os
import os

import redis
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

class RedisResource:
    REDIS_QUEUE_LOCATION = os.getenv('REDIS_QUEUE', 'localhost')
    CHUNK_QUEUE = 'queue:chunk'
    ENCODE_QUEUE = 'queue:encode'
    THUMBNAIL_QUEUE = 'queue:thumbnail'

    host, *port_info = REDIS_QUEUE_LOCATION.split(':')
    port = tuple()
    if port_info:
        port, *_ = port_info
        port = (int(port),)

    conn = redis.Redis(host=host, *port)

class Item(BaseModel):
    name: str

@app.post("/chunk")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.CHUNK_QUEUE,
        json.dumps(item.__dict__))
    return item

@app.post("/encode")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.ENCODE_QUEUE,
        json.dumps(item.__dict__))
    return item

@app.post("/thumbnail")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.THUMBNAIL_QUEUE,
        json.dumps(item.__dict__))
    return item