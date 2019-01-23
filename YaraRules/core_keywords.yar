/*
    This rule will match any of the keywords in the list
*/

rule core_keywords
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $tango_down = "TANGO DOWN" wide ascii nocase
        $antisec = "antisec" wide ascii nocase
        $hacked = "hacked by" wide ascii nocase
        $onion_url = /.*.\.onion/
        $nmap_scan = "Nmap scan report for" wide ascii nocase
        $enabled_sec = "enable secret" wide ascii nocase
        $enable_pass = "enable password" wide ascii nocase
    condition:
        any of them

}

rule dox
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $dox = "DOX" wide ascii nocase fullword
        $keyword1 = "name" wide ascii nocase
        $keyword2 = "dob" wide ascii nocase
        $keyword3 = "age" wide ascii nocase
        $keyword4 = "password" wide ascii nocase
        $keyword5 = "email" wide ascii nocase
    condition:
        $dox and 3 of ($keyword*)

}
