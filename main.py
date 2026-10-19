from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import re

app = FastAPI(title="OSINT Intern Triage Engine")

# Enables frontend app to send cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.api_route("/", methods=["GET", "HEAD"])
def health_check():
    return {
        "status": "online",
        "service": "OSINT Triage Engine",
        "regions_supported": ["Nigeria (+234)", "United Kingdom (+44)", "North America (+1)"],
        "endpoints": ["/api/lookup/phone", "/api/scan/email"]
    }

@app.get("/api/lookup/phone")
def lookup_phone(phone: str = Query(..., description="Phone number with country code")):
    """
    Normalizes carrier prefixes, detects line types (VoIP vs Mobile vs Landline),
    and identifies telecom routing for Nigeria (+234), UK (+44), and US/Canada (+1).
    """
    clean_digits = re.sub(r"\D", "", phone)
    
    carrier = "Unknown / International"
    line_type = "mobile"
    region = "International"
    is_voip = False
    details = ""

    # 1. UNITED KINGDOM (+44)
    if clean_digits.startswith("44") and len(clean_digits) in [11, 12, 13]:
        region = "United Kingdom"
        # Standard UK national number starts after the 44
        uk_national = clean_digits[2:]
        if uk_national.startswith("0"):
            uk_national = uk_national[1:]

        # UK Mobile allocations: starts with 7 (e.g., 071-079)
        if uk_national.startswith("7"):
            prefix = uk_national[:3]
            line_type = "mobile"
            
            # Personal numbers / VoIP / Virtual services masquerading as mobile
            if prefix in ["700", "701", "702", "703", "704", "705", "706", "707", "708", "709"]:
                carrier = "UK Personal / Find-Me-Follow-Me (Virtual VoIP)"
                line_type = "voip"
                is_voip = True
                details = "High fraud risk: UK 070 personal forwarding virtual number"
            # Major UK MNOs
            elif prefix in ["710", "740", "741", "742", "743", "744", "745", "750", "751", "752", "753", "758"]:
                carrier = "EE / BT Mobile"
            elif prefix in ["780", "781", "782", "783", "774", "771", "772", "773", "755", "778"]:
                carrier = "Vodafone UK"
            elif prefix in ["785", "786", "787", "790", "791", "792", "793", "794", "795", "796", "797", "798"]:
                carrier = "O2 UK (Virgin Media O2)"
            elif prefix in ["730", "731", "734", "736", "737", "738", "739"]:
                carrier = "Three UK (H3G)"
            else:
                carrier = "UK Mobile (MVNO / Regional Allocation)"

        # UK Landline allocations (01 and 02)
        elif uk_national.startswith("1") or uk_national.startswith("2"):
            line_type = "landline"
            if uk_national.startswith("20"):
                carrier = "UK Geographic (London Area)"
            elif uk_national.startswith("161"):
                carrier = "UK Geographic (Manchester Area)"
            elif uk_national.startswith("121"):
                carrier = "UK Geographic (Birmingham Area)"
            else:
                carrier = "UK Geographic (Landline)"

        # UK VoIP allocations (056 prefix dedicated to VoIP)
        elif uk_national.startswith("56"):
            carrier = "UK Dedicated VoIP (056)"
            line_type = "voip"
            is_voip = True

        # UK Non-geographic / Corporate (03, 0800, 0808, 0845, 0870)
        elif uk_national.startswith("80") or uk_national.startswith("800") or uk_national.startswith("808"):
            carrier = "UK Freephone / Corporate Virtual"
            line_type = "voip"
            is_voip = True
        elif uk_national.startswith("3") or uk_national.startswith("8"):
            carrier = "UK Non-Geographic / Special Service"
            line_type = "special"

    # 2. NIGERIA (+234)
    elif clean_digits.startswith("234") and len(clean_digits) >= 6:
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

    # 3. NORTH AMERICA (+1)
    elif clean_digits.startswith("1") and len(clean_digits) == 11:
        region = "North America"
        area_code = clean_digits[1:4]
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
        "is_voip": is_voip,
        "details": details
    }

@app.get("/api/scan/email")
def scan_email(email: str = Query(..., description="Target email to test")):
    """
    Executes holehe headlessly to check registered platform footprints.
    """
    clean_email = email.strip()
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", clean_email):
        return {"target": clean_email, "error": "Invalid email format", "status": "failed"}

    try:
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
