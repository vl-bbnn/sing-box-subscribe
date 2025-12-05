from fastapi import FastAPI
from api.app import config

app = FastAPI()


@app.get("/vpn/{id}")
async def get_config(id: str):
    return config(id)
