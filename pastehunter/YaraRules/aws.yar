rule aws_cli
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "aws s3 " ascii
        $a2 = "aws ec2 " ascii
        $a3 = "aws ecr " ascii
        $a4 = "aws cognito-identity" ascii
        $a5 = "aws iam "ascii
        $a6 = "aws waf " ascii

    condition:
        any of them

}

rule sw_bucket
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "s3.amazonaws.com" ascii

    condition:
        any of them



}
