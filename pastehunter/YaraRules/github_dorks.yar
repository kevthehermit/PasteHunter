/*
    These are rule derived from github-dorks (https://github.com/techgaun/github-dorks)
    github-dorks is under the Apache License 2.0:
    https://github.com/techgaun/github-dorks/blob/master/LICENSE
*/
rule NPMRegistry {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "NPM Registry files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "_auth" nocase
    condition:
        all of them and filename matches /.*\.npmrc$/is
}

rule DockerCfg {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Docker config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "auth" nocase
    condition:
        all of them and filename matches /.*\.dockercfg$/is
}
rule PrivateKeys {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Private key files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "private" nocase
    condition:
        all of them and (filename matches /.*\.pem$/is or filename matches /\.ppk$/is
                or filename matches /(\/|^)id_(r|d)sa$/is)
}
rule SQLDump {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "SQL dumps (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "mysql" nocase
        $ = "dump" nocase
    condition:
        all of them and (filename matches /.*\.sql$/is)
}
rule S3Credentials {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "S3 Credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "aws_access_key_id" nocase
    condition:
        filename matches /(\/|^)\.s3cfg$/is or filename matches /(\/|^)credentials$/is and all of them
}
rule WPConfig {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Wordpress config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)wp-config.php$/is
}
rule HTPasswd {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "htpasswd files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)\.htpasswd$/is
}
rule EnvFile {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = ".env files, Matches laravel, mailservers, and various CI and config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $db_usr = "DB_USERNAME"
        $mail_host = "MAIL_HOST=smtp."
        $excl = "homestead" nocase
    condition:
        filename matches /(\/|^)\.env/is and any of ($db_usr, $mail_host) and not $excl
}
rule GitCredentials {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = ".git-credentials files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)\.git-credentials$/is
}
rule PivotalToken {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "PivotalTracker token (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "PT_TOKEN"
    condition:
        any of them
}

rule BashProfile {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Sensitive info in profile files, specifically .bashrc and .bash_profile (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "password" nocase
        $ = "mailchimp" nocase
        $ = "aws" nocase
        $ = "secret" nocase
    condition:
        filename matches /(\/|^)\.bash(rc|_profile)$/is and any of them
}
rule AmazonCredentials {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Generic AWS credentials for RDS or EC2 (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $rds = "rds.amazonaws.com" nocase
        $ec2 = "ec2.amazonaws.com" nocase
        $pass = "password" nocase
    condition:
        $pass and ($rds or $ec2)
}
rule MongoLab {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "MongoLab Credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "mongolab.com" nocase
    condition:
        filename matches /.*(\.conf|\.yaml|\.yml|\.json)$/is and all of them
}
rule RoboMongo {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "RoboMongo Credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)robomongo\.json$/is
}
rule JSForce {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Salesforce Credentials for JSForce (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "jsforce" nocase
        $ = "conn.login" nocase
    condition:
        filename matches /.*js$/is and all of them
}
rule Salesforce {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Generic salesforce Credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "SF_USERNAME" nocase
        $ = "salesforce" nocase
    condition:
        all of them
}
rule Tugboat {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "DigitalOcean Tugboat Configurations (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "_tugboat"
    condition:
        filename matches /(\/|^)\.tugboat$/is and not any of them
}
rule Hub {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Hub files that contain oauth tokens (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = /oauth_token: [a-zA-Z0-9]+/ nocase
    condition:
        filename matches /(\/|^)hub$/is and any of them
}
rule NetRC {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Netrc files that contain 'password' or 'key' (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "password"
        $ = "key"
    condition:
        filename matches /(\/|^)\.?_?netrc/is and any of them
}
rule Filezilla {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Filezilla configuration files with passwords (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "Pass"
    condition:
        (filename matches /(\/|^)filezilla\.xml$/is or filename matches /(\/|^)recentservers.xml$/is) and any of them
}
rule Docker {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Docker authentication config (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "auths"
    condition:
        filename matches /(\/|^)config\.json$/is and any of them
}
rule IdeaKey {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "License Keys for IDEA IDEs (IntelliJ, PyCharm, etc) (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)idea[0-9]{0,}\.key$/is
}
rule DBServers {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Database servers (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)connections\.xml$/is
            or filename matches /(\/|^)\.pgpass$/is
}
rule Proftpd {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Proftpd configuration files created by cpanel (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)proftpdpasswd$/is
}
rule Ventrilo {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Ventrilo server configuration files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)ventrilo_srv\.ini/is
}
rule WinFrameClient {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "WinFrame-Client configuration used to connect to Citrix Application Servers (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "[WFClient] Password="
    condition:
        all of them and filename matches /.*\.ica/is
}
rule CounterStrikeRCON {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "RCON Credentials for CounterStrike servers (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "rcon" nocase
        $ = "password" nocase
    condition:
        all of them and filename matches /(\/|^)server\.cfg/is
}
rule JekyllGitHub {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Jekyll Token for GitHub (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "JEKYLL_GITHUB_TOKEN" nocase
    condition:
        all of them
}
rule SshdConfig {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "SSHD config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)sshd_config/is
}
rule DhcpConfig {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "DHCP Config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)dhcpd\.conf/is
}
rule Phoenix {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Phoenix prod config and secret files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "prod.secret.exs"
    condition:
        filename matches /(\/|^)prod\.secret\.exs/is or (filename matches /(\/|^)prod\.exs/is and not any of them)
}
rule JoomlaConfig {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Joomla config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "JConfig" nocase
        $ = "password" nocase
    condition:
        filename matches /(\/|^)configuration.php/is and all of them
}
rule PasswdFile {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Unix /etc/passwd files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "/bin/bash" nocase
        $ = "/bin/sh" nocase
        $ = "/usr/sbin/nologin" nocase
    condition:
        filename matches /(\/|^)passwd$/is and any of them
}
rule ShadowFile {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Unix /etc/shadow files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = ":17737:0:99999" nocase
        $ = "root:*:" nocase
        // MD5
        $ = "$1" nocase
        // SHA-256
        $ = "$5" nocase
        // SHA-1
        $ = "$6" nocase
    condition:
        filename matches /(\/|^)passwd$/is and any of them
}
rule Shodan {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Shodan API Keys (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = /shodan_api_key: [a-zA-Z0-9]+/ nocase
        $ = /shodan_api_key=[a-zA-Z0-9]+/ nocase
    condition:
        any of them
}
rule Avast {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Avast license files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "support.avast.com" nocase
    condition:
        all of them and (filename matches /.*\.avastlic$/is)
}
rule DBeaver {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "DBeaver configuration files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)dbeaver-data-sources.xml$/is
}
rule ESmtp {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = ".esmtpdrc files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "password" nocase
    condition:
        filename matches /(\/|^)\.esmtprc$/is and all of them
}
rule Homebrew {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Homebrew github tokens (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "HOMEBREW_GITHUB_API_TOKEN" nocase
    condition:
        all of them
}
rule MLab {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "MLab mongodb credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = ".mlab.com" nocase
        $ = "password" nocase
    condition:
        all of them
}
rule Firefox {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Firefox saved passwords (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)logins\.json$/is
}
rule CCCam {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "CCCam server config files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)CCCam\.cfg$/is
}
rule IRC {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Nickserv auth configs (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "msg nickserv identify" nocase
    condition:
        filename matches /(\/|^)config$/is and all of them
}
rule Django {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Django secret keys (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "SECRET_KEY" nocase
    condition:
        filename matches /(\/|^)settings.py$/is and all of them
}
rule RailsSecrets {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Ruby on rails secrets.yml files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "password" nocase
    condition:
        filename matches /(\/|^)secrets\.yml$/is and all of them
}
rule RailsMasterKey {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Rails master key files (used for decrypting credentials.yml.enc for Rails 5.2+) (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "password" nocase
    condition:
        filename matches /(\/|^)config\/master\.key$/is and all of them
}
rule AtomDeployments {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Multiple files created by different atom extensions for authentication (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)deployment-config\.json$/is or
        filename matches /(\/|^)remote-sync\.json$/is or
        filename matches /(\/|^)\.ftpconfig$/is
}
rule VscodeSftp {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "VSCode SFTP files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)\.vscode\/sftp\.json$/is
}
rule SublimeSftp {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Sublime SFTP files (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)sftp-config\.json$/is
}
rule JetbrainsCreds {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Jetbrains IDE webserver credentials with encoded passwords (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    condition:
        filename matches /(\/|^)WebServers\.xml$/is
}