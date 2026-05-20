rule Google_API_Key
{
    meta:
        description = "Hardcoded Google API key detected"
        severity = "HIGH"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $a = /AIza[0-9A-Za-z\-_]{35}/
    condition:
        $a
}

rule AWS_Access_Key
{
    meta:
        description = "AWS Access Key ID found in source"
        severity = "CRITICAL"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $a = /AKIA[0-9A-Z]{16}/
    condition:
        $a
}

rule Stripe_Live_Secret_Key
{
    meta:
        description = "Stripe live secret key hardcoded"
        severity = "CRITICAL"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $a = /sk_live_[0-9a-zA-Z]{24,}/
    condition:
        $a
}

rule GitHub_Personal_Token
{
    meta:
        description = "GitHub personal access token found"
        severity = "CRITICAL"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $a = /ghp_[0-9a-zA-Z]{36}/
    condition:
        $a
}

rule Private_Key_Block
{
    meta:
        description = "Private key material embedded in APK"
        severity = "CRITICAL"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $rsa  = "-----BEGIN RSA PRIVATE KEY-----"
        $ec   = "-----BEGIN EC PRIVATE KEY-----"
        $pkcs = "-----BEGIN PRIVATE KEY-----"
        $open = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        any of them
}

rule Firebase_Database_URL
{
    meta:
        description = "Firebase database URL hardcoded"
        severity = "MEDIUM"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $a = /https:\/\/[a-z0-9\-]+\.firebaseio\.com/
    condition:
        $a
}

rule Hardcoded_Password_Assignment
{
    meta:
        description = "Hardcoded password string in source"
        severity = "HIGH"
        category = "secrets"
        confidence = "MEDIUM"
    strings:
        $a = /password\s*=\s*"[^"]{4,}"/  nocase
        $b = /passwd\s*=\s*"[^"]{4,}"/    nocase
        $c = /pwd\s*=\s*"[^"]{4,}"/       nocase
    condition:
        any of them
}

rule JWT_Token_Hardcoded
{
    meta:
        description = "JWT token hardcoded in source"
        severity = "HIGH"
        category = "secrets"
        confidence = "MEDIUM"
    strings:
        $a = /eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}/
    condition:
        $a
}

rule Slack_Token
{
    meta:
        description = "Slack API token found"
        severity = "HIGH"
        category = "secrets"
        confidence = "HIGH"
    strings:
        $a = /xox[baprs]\-[0-9A-Za-z]{10,48}/
    condition:
        $a
}
