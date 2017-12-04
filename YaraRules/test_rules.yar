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
        $a1 = "Function" nocase wide ascii fullword
        $a2 = "CreateObject" nocase wide ascii fullword
        $a3  = "Wscript" nocase wide ascii fullword
        $a4 = "As Long" nocase wide ascii fullword
        $a5 = "run" nocase wide ascii fullword
        $b1 = "NtAllocateVirtualMemory" nocase wide ascii fullword
        $b2 = "NtWriteVirtualMemory" nocase wide ascii fullword


    condition:
        3 of them
}