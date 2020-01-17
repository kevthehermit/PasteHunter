/*
    This rule will look for Database elements
*/

rule db_connection
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /\b(mongodb|http|https|ftp|mysql|postgresql|oracle):\/\/(\S*):(\S*)@(\S*)\b/
        $n1 = "#EXTINF"
        $n2 = "m3u8"

    condition:
        $a and not any of ($n*)
}

rule db_structure
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "CREATE TABLE" nocase
        $b = "INSERT INTO" nocase
        $c = "VALUES" nocase
        $d = "ENGINE" nocase
        $e = "CHARSET" nocase
        $f = "NOT NULL" nocase
        $g = "varchar" nocase
        $h = "PRIMARY KEY"

    condition:
        5 of them
}

rule db_create_user
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "GRANT ALL PRIVILEGES" nocase
        $b = "IDENTIFIED BY" nocase
        $c = "GRANT SELECT" nocase
        $d = "CREATE USER" nocase

    condition:
        2 of them
}