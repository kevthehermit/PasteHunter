rule blacklist
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "#EXTINF:" nocase // IPTV stream Lists.
        $b = "--app-name=LeagueClient" nocase // League of Legends Debug Log
    condition:
        any of them

}