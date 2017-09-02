/*
    This rule will look for ducky / bunny code
*/

rule ducky_code
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "DELAY"
        $a2 = "GUI r"
        $a3 = "STRING"
        $a4 = "ENTER"
        $a5 = "DEFAULTDELAY"
        $a6 = "WINDOWS"
        $a7 = "SHIFT"
    condition:
        4 of them
}

rule bunny_code
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "ATTACKMODE"
        $a2 = "QUACK"
        $a3 = "ECM_ETHERNET"
        $a4 = "RNDIS_ETHERNET"
        $a5 = "LED"
        $a6 = "GET SWITCH_POSITION"
        $a7 = "REQUIRETOOL"
    condition:
        4 of them
}