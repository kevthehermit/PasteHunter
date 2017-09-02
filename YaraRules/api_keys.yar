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
    condition:
        any of ($a*) and any of ($hash*)

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
        all of them
}
