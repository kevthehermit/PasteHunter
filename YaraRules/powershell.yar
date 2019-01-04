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
        $a = "powershell" nocase
        $b = "IEX" nocase
        $c = "new-object" nocase
        $d = "webclient" nocase
        $e = "downloadstring" nocase
        $f = "-WindowStyle Hidden" nocase
        $g = "invoke" nocase
        $h = "bitsadmin" nocase
        $i = "certutil -decode" nocase
        $j = "hidden" nocase
        $k = "nop" nocase
        $l = "-e" nocase
    condition:
        4 of them

}