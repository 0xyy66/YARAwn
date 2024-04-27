rule lnk_sus_conhost{
        meta:
                description = "Detects suspicious LNK files (droppers) using conhost.exe"
                author = "0xyy66"
                date = "2024-04-27"
        strings:
                $lnk = {4C 00 00 00}
                $suspicious = "Windows\\System32\\cONhosT.exe" ascii nocase 
                $normal = "C:\\Windows\\System32\\conhost.exe" 
        condition:
                ($lnk at 0) and ($suspicious) and not ($normal)
}
