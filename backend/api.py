from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner.utils import parse_targets
from scanner.scanner import scan_targets
from scanner.ai_summary import build_scan_summary, generate_risk_explanation
import dataclasses
import json

app = FastAPI(title="Network Recon API")

# Allow CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    scan_mode: str = "fast"

class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)

@app.post("/api/scan")
def run_scan(request: ScanRequest):
    try:
        targets = parse_targets(request.target)
        if not targets:
            raise HTTPException(status_code=400, detail="Invalid target format or unable to resolve.")
            
        scan_mode = request.scan_mode if request.scan_mode in {"fast", "deep"} else "fast"
        results = scan_targets(targets, max_workers=10, scan_mode=scan_mode)
        summary = build_scan_summary(results)
        ai_explanation = generate_risk_explanation(summary)
        
        # Convert dataclasses to dicts for JSON serialization
        hosts = json.loads(json.dumps(results, cls=EnhancedJSONEncoder))
        return {
            "hosts": hosts,
            "summary": summary,
            "ai_explanation": ai_explanation,
            "scan_mode": scan_mode,
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
