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
        $enabled_sec = "enable secret" wide ascii nocase
        $enable_pass = "enable password" wide ascii nocase
        $ssh_priv = "BEGIN RSA PRIVATE KEY" wide ascii nocase
        $pgp_priv = "BEGIN PGP PRIVATE KEY" wide ascii nocase
        $DOX = " DOX" wide ascii nocase
        $hacked = "hacked by" wide ascii nocase
        $onion_url = /'.*.\.onion'/
    condition:
        any of them

}