/*
    These are test rules
*/

rule test_hex_MZ
{
    meta:
        author = "kevthehermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $mz_hex  = "4d5a" nocase wide ascii

    condition:
        $mz_hex at 0

}

rule test_vbscript
{
    meta:
        author = "kevthehermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "Function" nocase wide ascii fullword
        $b = "CreateObject" nocase wide ascii fullword
        $c  = "Wscript" nocase wide ascii fullword
        $d = "As Long" nocase wide ascii fullword
        $e = "run" nocase wide ascii fullword
        $f = "for each" nocase wide ascii fullword
        $g = "end function" nocase wide ascii fullword
        $h = "NtAllocateVirtualMemory" nocase wide ascii fullword
        $i = "NtWriteVirtualMemory" nocase wide ascii fullword


    condition:
        5 of them
}

rule test_autoit
{
    meta:
        author = "kevthehermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $tray = "NoTrayIcon" nocase wide ascii fullword
        $a = "iniread" nocase wide ascii fullword
        $b = "fileinstall" nocase wide ascii fullword
        $c  = "EndFunc" nocase wide ascii fullword
        $d = "FileRead" nocase wide ascii fullword
        $e = "DllStructSetData" nocase wide ascii fullword
        $f = "Global Const" nocase wide ascii fullword
        $g = "Run(@AutoItExe" nocase wide ascii fullword
        $h = "StringReplace" nocase wide ascii fullword
        $i = "filewrite" nocase wide ascii fullword



    condition:
        ($tray and 3 of them) or (5 of them)
}