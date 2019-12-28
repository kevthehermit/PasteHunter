/*
    These rules attempt to find email leaks
*/

rule email_filter
{
    meta:
        author = "@kovacsbalu"
        info = "Better email pattern"
        reference = "https://github.com/securenetworx/PasteHunter/tree/fix-email-filter"

    strings:
	$email_add = /\b[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-]\b/
    condition:
        #email_add > 20

}


