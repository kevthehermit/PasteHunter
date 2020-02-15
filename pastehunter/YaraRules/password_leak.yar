/*
    These rules attempt to find password leaks / dumps
*/

rule password_list
{
    meta:
        author = "@KevTheHermit and @Plazmaz"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        // Email validation---------------------------------------------------V
        // Optional quotes -----------------------------------------------------v
        // Seperator char (:|,) ------------------------------------------------------v
        // Continue until word boundary or space ----------------------------------------------v
        $data_format = /\b[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-]["|']?(:|\|)[^\b\s]+\b/

    condition:
        #data_format > 10

}