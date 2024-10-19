import requests

# Replace with your endpoint URL
ENDPOINT_URL = "http://localhost:8080/worker/verifyEKCertificate"  # Example endpoint
# Replace with your test EK certificate
test_ek_certificate = """
-----BEGIN CERTIFICATE-----
MIIElTCCA32gAwIBAgIEFMzNOTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC
REUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwR
T1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkg
UlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMB4XDTE2MDEwMTEzMTAyMloXDTMxMDEw
MTEzMTAyMlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAISFY3i9
WciX46z/ALiAKejoHbxDOTyldeUPYwNVxU9rOEuWl9EvB+cn//ecWPeVXjj1rqYP
wZztCDPORjHa93JnW+z75brKmtekC1O8R9ii8oAyEHmwvvgxHd8oOLqHBfTvodn2
1pE6gxbeZCETU6FcpqVMHJJQBpNocX7nOX/2QqJW10MkUN+b8EodEv7xJ5dFV7B6
kG9UowP1hqgSngG4gOrm3wAfXREsU0ne9KYTSZwXWb6JErIM0OqY/1Uv4fNmd5BQ
UJwXQK4WKfQlT5++d2oJHpYkF99CHM4l/JlSg1+apZ80cGfNA9nhuk/E89lrc7MM
ITuVMCij4Mu9XqMCAwEAAaOCAZEwggGNMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEF
BQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDMv
T3B0aWdhUnNhTWZyQ0EwMDMuY3J0MA4GA1UdDwEB/wQEAwIAIDBRBgNVHREBAf8E
RzBFpEMwQTEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDETMBEGBWeBBQICDAhTTEIg
OTY2NTESMBAGBWeBBQIDDAdpZDowNTI4MAwGA1UdEwEB/wQCMAAwUAYDVR0fBEkw
RzBFoEOgQYY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0Ew
MDMvT3B0aWdhUnNhTWZyQ0EwMDMuY3JsMBUGA1UdIAQOMAwwCgYIKoIUAEQBFAEw
HwYDVR0jBBgwFoAUQLhoK40YRQorBoSdm1zZb0zd9L4wEAYDVR0lBAkwBwYFZ4EF
CAEwIQYDVR0JBBowGDAWBgVngQUCEDENMAsMAzIuMAIBAAIBdDANBgkqhkiG9w0B
AQsFAAOCAQEApynlEZGc4caT7bQJjhrvOtv4RFu3FNA9hgsF+2BGltsumqo9n3nU
GoGt65A5mJAMCY1gGF1knvUFq8ey+UuIFw3QulHGENOiRu0aT3x9W7c6BxQIDFFC
PtA+Qvvg+HJJ6XjihQRc3DU01HZm3xD//fGIDuYasZwBd2g/Ejedp2tKBl2M98FO
48mbZ4WtaPrEALn3UQMf27pWqe2hUKFSKDEurijnchsdmRjTmUEWM1/9GFkh6IrT
YvRBngNqOffJ+If+PI3x2GXkGnzsA6IxroEY9CwOhmNp+6xbAgqUedd5fWMLBN3Q
MjHSp1Sl8wp00xRztfh0diBdicy3Hbn03g==
-----END CERTIFICATE-----
"""
test_ek = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhIVjeL1ZyJfjrP8AuIAp
6OgdvEM5PKV15Q9jA1XFT2s4S5aX0S8H5yf/95xY95VeOPWupg/BnO0IM85GMdr3
cmdb7Pvlusqa16QLU7xH2KLygDIQebC++DEd3yg4uocF9O+h2fbWkTqDFt5kIRNT
oVympUwcklAGk2hxfuc5f/ZColbXQyRQ35vwSh0S/vEnl0VXsHqQb1SjA/WGqBKe
AbiA6ubfAB9dESxTSd70phNJnBdZvokSsgzQ6pj/VS/h82Z3kFBQnBdArhYp9CVP
n753agkeliQX30IcziX8mVKDX5qlnzRwZ80D2eG6T8Tz2WtzswwhO5UwKKPgy71e
owIDAQAB
-----END PUBLIC KEY-----
"""

def test_validate_ek_certificate():
    """Test the EK certificate validation endpoint."""
    payload = {
        "endorsementKey": test_ek,
        "EKCertificate": test_ek_certificate
    }

    try:
        response = requests.post(ENDPOINT_URL, json=payload)

        if response.status_code == 200:
            print("Validation successful:", response.json())
        else:
            print(f"Validation failed. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")

if __name__ == "__main__":
    test_validate_ek_certificate()
