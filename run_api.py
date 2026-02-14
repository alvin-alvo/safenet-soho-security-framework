import uvicorn
import asyncio
import sys

if __name__ == "__main__":
    # FIX: Force ProactorEventLoop on Windows for subprocess support
    # (Uvicorn's default reload mechanism can sometimes use Selector on Windows)
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
    print(f"SafeNet API Launcher")
    print(f"Platform: {sys.platform}")
    print(f"Event Loop Policy: {asyncio.get_event_loop_policy()}")
    print("-" * 50)
    
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=False)
