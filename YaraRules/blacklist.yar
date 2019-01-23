rule blacklist
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "#EXTINF:" nocase // IPTV stream Lists.
        $b = "--app-name=LeagueClient" nocase // League of Legends Debug Log
        $c = "common.application_name: LeagueClient" // League of Legends Debug Log
        $d = /java\.(util|lang|io)/ // Minecraft and java errors
        $e = "Traceback (most recent call last)"
        $f = /define\(.*?\)|require_once\(.*?\)/
        $g = "Technic Launcher is starting" // Minecraft mod dumps
        $h = "OTL logfile created on" // 
    condition:
        any of them

}