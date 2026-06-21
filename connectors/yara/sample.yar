rule SUSP_PowerShell_Encoded : powershell obfuscation
{
    meta:
        description = "Detects base64-encoded PowerShell command lines"
        author = "XORCISM"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $a = "-enc" nocase
        $b = "FromBase64String" nocase
        $c = "-nop" nocase
    condition:
        2 of them
}

rule Mimikatz_Memory : credential_access apt
{
    meta:
        description = "Mimikatz strings in memory (T1003.001)"
        author = "XORCISM"
    strings:
        $s1 = "sekurlsa::logonpasswords"
        $s2 = "gentilkiwi"
    condition:
        any of them
}
