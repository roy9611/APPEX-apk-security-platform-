rule Debuggable_Application
{
    meta:
        description = "App has android:debuggable=true set"
        severity = "CRITICAL"
        category = "manifest"
        remediation = "Remove debuggable=true before release"
    strings:
        $a = "android:debuggable=\"true\""
        $b = "debuggable=\"true\""
    condition:
        any of them
}

rule Backup_Enabled
{
    meta:
        description = "App allows ADB backup of private data"
        severity = "HIGH"
        category = "manifest"
    strings:
        $a = "android:allowBackup=\"true\""
    condition:
        $a
}

rule Cleartext_Traffic_Manifest
{
    meta:
        description = "App permits cleartext HTTP traffic"
        severity = "HIGH"
        category = "manifest"
    strings:
        $a = "android:usesCleartextTraffic=\"true\""
    condition:
        $a
}

rule Exported_Content_Provider
{
    meta:
        description = "ContentProvider exported without permission"
        severity = "CRITICAL"
        category = "manifest"
    strings:
        $provider = "<provider"
        $exported  = "android:exported=\"true\""
        $no_perm   = "android:permission"
    condition:
        $provider and $exported and not $no_perm
}

rule Custom_Permission_Missing
{
    meta:
        description = "Exported component has no permission protection"
        severity = "HIGH"
        category = "manifest"
    strings:
        $exported = "android:exported=\"true\""
    condition:
        #exported >= 3
}
