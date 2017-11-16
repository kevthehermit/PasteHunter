/*
    These rules attempt to find password leaks / dumps
*/

rule email_list
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $email_add = /\b[\w\.-]+@[\w\.-]+\.\w+\b/
    condition:
        #email_add > 20

}

/*
rule password_list
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $data_format = /\b([@a-zA-Z0-9._-]{5,})(:|\|)(.*)\b/

    condition:
        #data_format > 10

}
*/