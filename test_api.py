"""Quick test for the SmartISMS web API."""
import requests

with open('datasets/cisco/cisco_secure_router.conf', 'rb') as f:
    resp = requests.post('http://localhost:5000/api/evaluate',
        files={'config_file': ('cisco_secure_router.conf', f)},
        data={'standards': 'CIS,ISO27001,PCI-DSS,HIPAA'}
    )

print("Status:", resp.status_code)
print("Response:", resp.text[:2000])
