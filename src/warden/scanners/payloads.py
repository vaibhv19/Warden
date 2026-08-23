"""Payload definitions for Warden specialized security scanners."""

# SQL Injection Payloads
# Quote error, Boolean-based, and Time-based patterns
SQLI_PAYLOADS = [
    # Quote/Syntax patterns
    {
        "type": "error",
        "payload": "'",
        "description": "Single quote syntax trigger",
    },
    {
        "type": "error",
        "payload": '"',
        "description": "Double quote syntax trigger",
    },
    # Boolean patterns
    {
        "type": "boolean_true",
        "payload": "' OR '1'='1",
        "description": "Boolean always-true condition",
    },
    {
        "type": "boolean_false",
        "payload": "' OR '1'='2",
        "description": "Boolean always-false condition",
    },
    # Time-based patterns
    {
        "type": "time",
        "payload": "sleep",  # will trigger custom time.sleep(5) in test_target if it contains this keyword
        "description": "Simulated time-based trigger",
        "delay": 5,
    },
]

# Cross-Site Scripting (XSS) Payloads
# Reflected tags, quotes breakout, and event handlers
XSS_PAYLOADS = [
    {
        "payload": "<script>alert(1)</script>",
        "description": "Standard script tag injection",
    },
    {
        "payload": '"><script>alert(1)</script>',
        "description": "Script tag breakout pattern",
    },
    {
        "payload": "<img src=x onerror=alert(1)>",
        "description": "Event handler element injection",
    },
]

# Authentication bypass parameters
AUTH_BYPASS_HEADERS = [
    {"Authorization": "Bearer invalid_token"},
    {"Authorization": "Basic aW52YWxpZDppbnZhbGlk"},  # invalid:invalid
    {},  # empty header
]
