/*
    This rule will look for standard API Keys.
*/

rule generic_api
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "apikey" nocase
        $a2 = "api_key" nocase
        $hash32 = /\b[a-fA-F\d]{32}\b/
        $hash64 = /\b[a-fA-F\d]{64}\b/
        $n1 = "#EXTINF"
        $n2 = "m3u8"
        $n3 = "Chocolatey is running"

    condition:
        (any of ($a*)) and (any of ($hash*)) and (not any of ($n*))

}

rule twitter_api
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "consumer_key" nocase
        $b = "consumer_secret" nocase
        $c = "access_token" nocase
    condition:
        all of them

}

rule google_api
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /\bAIza.{35}\b/
    condition:
        any of them
}

rule slack_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /(xox(p|b|o|a)-[0-9]{9,12}-[0-9]{9,12}-[0-9]{9,12}-[a-z0-9]{32})/
        $b = "hooks.slack.com" nocase
    condition:
        any of them
}

rule github_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /[g|G][i|I][t|T][h|H][u|U][b|B].*[[\'|"]0-9a-zA-Z]{35,40}[\'|"]/
    condition:
        any of them
}

rule aws_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /AKIA[0-9A-Z]{16}/
    condition:
        any of them
}

rule heroku_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/
    condition:
        any of them
}

rule discord_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "DiscordRelay.BotToken" nocase
        $b = "discordapp.com/api/webhooks" nocase
    condition:
        any of them
}
