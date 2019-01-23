/*
    This rule will look for common powershell elements
*/

rule powershell
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "powershell" nocase
        $a2 = "IEX" nocase
        $a3 = "new-object" nocase
        $a4 = "webclient" nocase
        $a5 = "downloadstring" nocase
        $a6 = "-WindowStyle Hidden" nocase
        $a7 = "invoke" nocase
        $a8 = "bitsadmin" nocase
        $a9 = "certutil -decode" nocase
        $a10 = "hidden" nocase
        $a11 = "nop" nocase
        $a12 = "-e" nocase

        $not1 = "chocolatey" nocase
        $not2 = "XmlConfiguration is now operational" nocase
    condition:
        4 of ($a*) and not any of ($not*)

}