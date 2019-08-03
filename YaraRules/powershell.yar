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
        $a1 = "powershell" fullword wide ascii nocase
        $a2 = "IEX" fullword wide ascii nocase
        $a3 = "new-object" fullword wide ascii nocase
        $a4 = "webclient" fullword wide ascii nocase
        $a5 = "downloadstring" fullword wide ascii nocase
        $a6 = "-WindowStyle Hidden" fullword wide ascii nocase
        $a7 = "invoke" fullword wide ascii nocase
        $a8 = "bitsadmin" fullword wide ascii nocase
        $a9 = "certutil -decode" fullword wide ascii nocase
        $a10 = "hidden" fullword wide ascii nocase
        $a11 = "nop" fullword wide ascii nocase
        $a12 = "Invoke-" fullword wide ascii nocase
        $a13 = "FromBase64String(" fullword wide ascii nocase



        $not1 = "chocolatey" nocase
        $not2 = "XmlConfiguration is now operational" nocase
    condition:
        4 of ($a*) and not any of ($not*)

}
