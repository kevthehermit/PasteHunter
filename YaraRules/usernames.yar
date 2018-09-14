/*
    This rule will match any of the keywords in the list
*/

rule usernames
{
    meta:
        author = "@ositbx"
        info = "Ephemeral list of pastebin usernames scraping"
        reference = ""

    strings:
        $s1 = "bank_security" ascii nocase
        $s2 = "vk_intel" ascii nocase
        $s3 = "James_inthe_box" ascii nocase
		$s4 = "MalwareMessiagh" ascii nocase
    condition:
        any of them

}
