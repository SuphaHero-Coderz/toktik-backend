import socketio
sio = socketio.AsyncServer(cors_allows_origin='*', async_mode='asgi')

@sio.event
def connect(sid, environ):
    print(f"connect with sid: {sid}, environ: {environ}")

@sio.event
def disconnect(sid):
    print(f"disconnect {sid}")
