/*
    This rule will look for base64 encoded data.
*/

rule b64_exe
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_exe = /TV(oA|pB|pQ|qA|qQ|ro)/
    condition:
        $b64_exe

}

rule b64_elf
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_elf = "f0VM"
    condition:
        $b64_elf at 0

}

rule b64_zip
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_zip = "UEs"
    condition:
        $b64_zip at 0

}

rule b64_rar
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_rar = "UmFy"
    condition:
        $b64_rar at 0

}


rule b64_gzip
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_gzip = "H4sI"
    condition:
        $b64_gzip at 0

}

rule b64_url
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "aHR0cDov" // http/s
        $b = "SFRUUDov" // HTTP/S
        $c = "d3d3Lg" // www.
        $d = "V1dXLg" // WWW.
    condition:
        any of them

}