rule World_Readable_Storage
{
    meta:
        description = "File or preferences opened as world-readable"
        severity = "HIGH"
        category = "storage"
        confidence = "HIGH"
    strings:
        $a = "MODE_WORLD_READABLE"
    condition:
        $a
}

rule World_Writable_Storage
{
    meta:
        description = "File or preferences opened as world-writable"
        severity = "HIGH"
        category = "storage"
        confidence = "HIGH"
    strings:
        $a = "MODE_WORLD_WRITEABLE"
    condition:
        $a
}

rule External_Storage_Sensitive
{
    meta:
        description = "App writes to external storage"
        severity = "MEDIUM"
        category = "storage"
        confidence = "MEDIUM"
    strings:
        $a = "getExternalStorageDirectory"
        $b = "getExternalFilesDir"
    condition:
        any of them
}

rule Unencrypted_SQLite
{
    meta:
        description = "SQLite database created without encryption"
        severity = "MEDIUM"
        category = "storage"
        confidence = "MEDIUM"
    strings:
        $create  = "openOrCreateDatabase"
        $cipher  = "SQLCipher"
        $cipher2 = "net.sqlcipher"
    condition:
        $create and not $cipher and not $cipher2
}

rule Sensitive_Data_Logging
{
    meta:
        description = "Sensitive data potentially written to logs"
        severity = "MEDIUM"
        category = "storage"
        confidence = "LOW"
    strings:
        $log1 = "Log.d"
        $log2 = "Log.v"
        $pass = /[Pp]assword/
        $key  = /[Aa][Pp][Ii][Kk]ey/
        $tok  = /[Tt]oken/
    condition:
        ($log1 or $log2) and ($pass or $key or $tok)
}
