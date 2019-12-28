/*
    Just some General Rules. Dont need a file per rule.
*/

rule php_obfuscation
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "eval(" nocase
        $b = "gzinflate(" nocase
        $c = "base64_decode("
        $d = "\\142\\x61\\163\\145\\x36\\x34\\137\\144\\x65\\x63\\x6f\\x64\\x65"
        $e = "str_rot13("

    condition:
        2 of them
}