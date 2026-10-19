from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import re

app = FastAPI(title="OSINT Intern Triage Engine")

# Enables your frontend app to send cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "OSINT Triage Engine",
        "endpoints": ["/api/lookup/phone", "/api/scan/email"]
    }

@app.get("/api/lookup/phone")
def lookup_phone(phone: str = Query(..., description="Phone number with country code")):
    """
    Normalizes carrier prefixes, detects line types (VoIP vs Mobile),
    and identifies major regional telecom routing.
    """
    clean_digits = re.sub(r"\D", "", phone)
    
    carrier = "Unknown / International"
    line_type = "mobile"
    region = "International"
    is_voip = False
    
    # Check for Nigerian dial code (+234)
    if clean_digits.startswith("234") and len(clean_digits) >= 6:
        region = "Nigeria"
        prefix = clean_digits[3:6]
        
        if prefix in ["803", "806", "703", "706", "813", "816", "810", "814", "903", "906", "913", "916"]:
            carrier = "MTN Nigeria"
        elif prefix in ["802", "808", "708", "812", "701", "902", "901", "904", "907", "912"]:
            carrier = "Airtel Nigeria"
        elif prefix in ["805", "807", "705", "815", "811", "905", "915"]:
            carrier = "Globacom (Glo)"
        elif prefix in ["809", "817", "818", "909", "908"]:
            carrier = "9mobile"
        else:
            carrier = "Fixed/Special Exchange"
            line_type = "landline"

    # Common North American VoIP and virtual patterns (+1)
    elif clean_digits.startswith("1") and len(clean_digits) == 11:
        region = "North America"
        area_code = clean_digits[1:4]
        # Flag common VoIP / toll-free prefixes
        if area_code in ["800", "888", "877", "866", "855", "844", "833"]:
            carrier = "Toll-Free Virtual"
            line_type = "voip"
            is_voip = True
        else:
            carrier = f"NANPA Region ({area_code})"

    return {
        "raw_input": phone,
        "clean_digits": clean_digits,
        "region": region,
        "carrier": carrier,
        "line_type": line_type,
        "is_voip": is_voip
    }

@app.get("/api/scan/email")
def scan_email(email: str = Query(..., description="Target email to test")):
    """
    Executes holehe headlessly to check registered platform footprints.
    """
    clean_email = email.strip()
    
    # Basic email format validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", clean_email):
        return {"target": clean_email, "error": "Invalid email format", "status": "failed"}

    try:
        # Run holehe via command-line interface in the cloud container
        cmd = ["holehe", clean_email, "--only-used", "--no-color"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        
        found_platforms = []
        for line in result.stdout.splitlines():
            if "[+]" in line:
                platform_name = line.replace("[+]", "").strip()
                if platform_name:
                    found_platforms.append(platform_name)

        return {
            "target": clean_email,
            "registered_platforms": found_platforms,
            "count": len(found_platforms),
            "status": "success"
        }
    except subprocess.TimeoutExpired:
        return {"target": clean_email, "error": "Scan request timed out", "status": "failed"}
    except Exception as err:
        return {"target": clean_email, "error": str(err), "status": "failed"}
