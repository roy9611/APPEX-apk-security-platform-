rule TrustManager_Bypass
{
    meta:
        description = "Custom TrustManager accepts all certificates"
        severity = "CRITICAL"
        category = "network"
        confidence = "HIGH"
    strings:
        $tm    = "TrustManager"
        $check = "checkServerTrusted"
    condition:
        $tm and $check
}

rule HostnameVerifier_Bypass
{
    meta:
        description = "HostnameVerifier returns true for all hosts"
        severity = "CRITICAL"
        category = "network"
        confidence = "HIGH"
    strings:
        $hv  = "HostnameVerifier"
        $ret = "return true"
    condition:
        $hv and $ret
}

rule Cleartext_Traffic_Config
{
    meta:
        description = "Network security config allows cleartext"
        severity = "HIGH"
        category = "network"
        confidence = "HIGH"
    strings:
        $a = "cleartextTrafficPermitted=\"true\""
    condition:
        $a
}

rule User_CA_Trust
{
    meta:
        description = "App trusts user-installed CA certificates"
        severity = "HIGH"
        category = "network"
        confidence = "HIGH"
    strings:
        $a = "certificates src=\"user\""
        $b = "<certificates src=\"user\"/>"
    condition:
        any of them
}

rule No_Certificate_Pinning
{
    meta:
        description = "No certificate pinning configured"
        severity = "MEDIUM"
        category = "network"
        confidence = "MEDIUM"
    strings:
        $nsc = "network_security_config"
        $pin = "pin-set"
    condition:
        $nsc and not $pin
}

rule HTTP_URL_Hardcoded
{
    meta:
        description = "Hardcoded HTTP URL found in source"
        severity = "LOW"
        category = "network"
        confidence = "MEDIUM"
    strings:
        $a = /http:\/\/[a-zA-Z0-9][a-zA-Z0-9\.\-]{4,}/
        $b = "schemas.android.com"
        $c = "localhost"
        $d = "127.0.0.1"
        $e = "10.0.2.2"
    condition:
        $a and not $b and not $c and not $d and not $e
}
