from fastapi import FastAPI
import uvicorn
from routers import user

app = FastAPI()

app.include_router(user.router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
