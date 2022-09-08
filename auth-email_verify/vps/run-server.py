import sys
sys.dont_write_bytecode = True

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8080,
        log_level="info",
        reload=True
    )