from inputs.ixio import IxDotIoSite
test_data = '''
<body>
2CmG
<a href="/2CmG">[r]</a> <a href="/2CmG/">[h]</a>
@ Thu Oct 29 07:00:19 2020
</div>
</div>
<div class="t">
2CmF
<a href="/2CmF">[r]</a> <a href="/2CmF/">[h]</a>
@ Thu Oct 29 07:00:14 2020
</div>
</div>
<div class="t">
2CmE
<a href="/2CmE">[r]</a> <a href="/2CmE/">[h]</a>
@ Thu Oct 29 07:00:13 2020
</div>
</div>
<div class="t">
2CmD
<a href="/2CmD">[r]</a> <a href="/2CmD/">[h]</a>
@ Thu Oct 29 06:47:22 2020
</div>
</div>
<div class="t">
2CmC
<a href="/2CmC">[r]</a> <a href="/2CmC/">[h]</a>
@ Thu Oct 29 06:26:48 2020
</div>
</div>
<div class="t">
2CmB
<a href="/2CmB">[r]</a> <a href="/2CmB/">[h]</a>
@ Thu Oct 29 06:21:48 2020
</div>
</div>
<div class="t">
2CmA
<a href="/2CmA">[r]</a> <a href="/2CmA/">[h]</a>
@ Thu Oct 29 06:19:33 2020
</div>
</div>
<div class="t">
2Cmz
<a href="/2Cmz">[r]</a> <a href="/2Cmz/">[h]</a>
@ Thu Oct 29 06:08:17 2020
</div>
</div>
<div class="t">
2Cmy
<a href="/2Cmy">[r]</a> <a href="/2Cmy/">[h]</a>
@ Thu Oct 29 06:00:16 2020
</div>
</div>
<div class="t">
2Cmx
<a href="/2Cmx">[r]</a> <a href="/2Cmx/">[h]</a>
@ Thu Oct 29 06:00:14 2020
</div>
</div>
<div class="t">
2Cmw
<a href="/2Cmw">[r]</a> <a href="/2Cmw/">[h]</a>
@ Thu Oct 29 05:03:04 2020
</div>
</div>
<div class="t">
2Cmv
<a href="/2Cmv">[r]</a> <a href="/2Cmv/">[h]</a>
@ Thu Oct 29 05:03:02 2020
</div>
</div>
<div class="t">
2Cmu
<a href="/2Cmu">[r]</a> <a href="/2Cmu/">[h]</a>
@ Thu Oct 29 05:00:09 2020
</div>
</div>
<div class="t">
2Cmt
<a href="/2Cmt">[r]</a> <a href="/2Cmt/">[h]</a>
@ Thu Oct 29 04:58:15 2020
</div>
</div>
<div class="t">
2Cms
<a href="/2Cms">[r]</a> <a href="/2Cms/">[h]</a>
@ Thu Oct 29 04:57:39 2020
</div>
</div>
<div class="t">
2Cmr
<a href="/2Cmr">[r]</a> <a href="/2Cmr/">[h]</a>
@ Thu Oct 29 04:57:31 2020
</div>
</div>
<div class="t">
2Cmq
<a href="/2Cmq">[r]</a> <a href="/2Cmq/">[h]</a>
@ Thu Oct 29 04:57:24 2020
</div>
</div>
<div class="t">
2Cmp
<a href="/2Cmp">[r]</a> <a href="/2Cmp/">[h]</a>
@ Thu Oct 29 04:51:45 2020
</div>
</div>
<div class="t">
2Cmo
<a href="/2Cmo">[r]</a> <a href="/2Cmo/">[h]</a>
@ Thu Oct 29 04:10:10 2020
</div>
</div>
<div class="t">
2Cmn
<a href="/2Cmn">[r]</a> <a href="/2Cmn/">[h]</a>
@ Thu Oct 29 04:09:34 2020
</div>
</div>
<div class="t">
2Cmm
<a href="/2Cmm">[r]</a> <a href="/2Cmm/">[h]</a>
@ Thu Oct 29 04:02:17 2020
</div>
</div>
<div class="t">
2Cml
<a href="/2Cml">[r]</a> <a href="/2Cml/">[h]</a>
@ Thu Oct 29 04:00:14 2020
</div>
</div>
<div class="t">
2Cmk
<a href="/2Cmk">[r]</a> <a href="/2Cmk/">[h]</a>
@ Thu Oct 29 04:00:04 2020
</div>
</div>
<div class="t">
2Cmj
<a href="/2Cmj">[r]</a> <a href="/2Cmj/">[h]</a>
@ Thu Oct 29 03:58:55 2020
</div>
</div>
<div class="t">
2Cmi
<a href="/2Cmi">[r]</a> <a href="/2Cmi/">[h]</a>
@ Thu Oct 29 03:57:40 2020
</div>
</div>
<div class="t">
2Cmh
<a href="/2Cmh">[r]</a> <a href="/2Cmh/">[h]</a>
@ Thu Oct 29 03:50:57 2020
</div>
</div>
<div class="t">
2Cmg
<a href="/2Cmg">[r]</a> <a href="/2Cmg/">[h]</a>
@ Thu Oct 29 03:42:28 2020
</div>
</div>
<div class="t">
2Cmf
<a href="/2Cmf">[r]</a> <a href="/2Cmf/">[h]</a>
@ Thu Oct 29 03:40:56 2020
</div>
</div>
<div class="t">
2Cme
<a href="/2Cme">[r]</a> <a href="/2Cme/">[h]</a>
@ Thu Oct 29 03:27:14 2020
</div>
</div>
<div class="t">
2Cmd
<a href="/2Cmd">[r]</a> <a href="/2Cmd/">[h]</a>
@ Thu Oct 29 03:26:44 2020
</div>
</div>
<div class="t">
2Cmc
<a href="/2Cmc">[r]</a> <a href="/2Cmc/">[h]</a>
@ Thu Oct 29 03:26:29 2020
</div>
</div>
<div class="t">
2Cmb
<a href="/2Cmb">[r]</a> <a href="/2Cmb/">[h]</a>
@ Thu Oct 29 03:22:12 2020
</div>
</div>
<div class="t">
2Cma
<a href="/2Cma">[r]</a> <a href="/2Cma/">[h]</a>
@ Thu Oct 29 03:19:14 2020
</div>
</div>
<div class="t">
2Cm9
<a href="/2Cm9">[r]</a> <a href="/2Cm9/">[h]</a>
@ Thu Oct 29 03:19:00 2020
</div>
</div>
<div class="t">
2Cm8
<a href="/2Cm8">[r]</a> <a href="/2Cm8/">[h]</a>
@ Thu Oct 29 03:18:46 2020
</div>
</div>
<div class="t">
2Cm7
<a href="/2Cm7">[r]</a> <a href="/2Cm7/">[h]</a>
@ Thu Oct 29 03:18:05 2020
</div>
</div>
<div class="t">
2Cm6
<a href="/2Cm6">[r]</a> <a href="/2Cm6/">[h]</a>
@ Thu Oct 29 03:00:16 2020
</div>
</div>
<div class="t">
2Cm5
<a href="/2Cm5">[r]</a> <a href="/2Cm5/">[h]</a>
@ Thu Oct 29 02:59:56 2020
</div>
</div>
<div class="t">
2Cm4
<a href="/2Cm4">[r]</a> <a href="/2Cm4/">[h]</a>
@ Thu Oct 29 02:54:27 2020
</div>
</div>
<div class="t">
2Cm3
<a href="/2Cm3">[r]</a> <a href="/2Cm3/">[h]</a>
@ Thu Oct 29 02:30:04 2020
</div>
</div>
<div class="t">
2Cm1
<a href="/2Cm1">[r]</a> <a href="/2Cm1/">[h]</a>
@ Thu Oct 29 02:09:03 2020
</div>
</div>
<div class="t">
2Cm0
<a href="/2Cm0">[r]</a> <a href="/2Cm0/">[h]</a>
@ Thu Oct 29 02:04:08 2020
</div>
</div>
<div class="t">
2ClZ
<a href="/2ClZ">[r]</a> <a href="/2ClZ/">[h]</a>
@ Thu Oct 29 02:02:27 2020
</div>
</div>
<div class="t">
2ClY
<a href="/2ClY">[r]</a> <a href="/2ClY/">[h]</a>
@ Thu Oct 29 02:00:14 2020
</div>
</div>
<div class="t">
2ClX
<a href="/2ClX">[r]</a> <a href="/2ClX/">[h]</a>
@ Thu Oct 29 02:00:13 2020
</div>
</div>
<div class="t">
2ClW
<a href="/2ClW">[r]</a> <a href="/2ClW/">[h]</a>
@ Thu Oct 29 02:00:08 2020
</div>
</div>
<div class="t">
2ClV
<a href="/2ClV">[r]</a> <a href="/2ClV/">[h]</a>
@ Thu Oct 29 01:56:47 2020
</div>
</div>
<div class="t">
2ClU
<a href="/2ClU">[r]</a> <a href="/2ClU/">[h]</a>
@ Thu Oct 29 01:41:09 2020
</div>
</div>
<div class="t">
2ClS
<a href="/2ClS">[r]</a> <a href="/2ClS/">[h]</a>
@ Thu Oct 29 01:30:02 2020
</div>
</div>
<div class="t">
2ClR
<a href="/2ClR">[r]</a> <a href="/2ClR/">[h]</a>
@ Thu Oct 29 01:19:24 2020
</div>
</div>
<div class="t">
2ClQ
<a href="/2ClQ">[r]</a> <a href="/2ClQ/">[h]</a>
@ Thu Oct 29 01:17:03 2020
</div>
</div>
<div class="t">
2ClP
<a href="/2ClP">[r]</a> <a href="/2ClP/">[h]</a>
@ Thu Oct 29 01:00:13 2020
</div>
</div>
<div class="t">
2ClO
<a href="/2ClO">[r]</a> <a href="/2ClO/">[h]</a>
@ Thu Oct 29 01:00:09 2020
</div>
</div>
<div class="t">
2ClN
<a href="/2ClN">[r]</a> <a href="/2ClN/">[h]</a>
@ Thu Oct 29 00:46:53 2020
</div>
</div>
<div class="t">
2ClM
<a href="/2ClM">[r]</a> <a href="/2ClM/">[h]</a>
@ Thu Oct 29 00:42:01 2020
</div>
</div>
<div class="t">
2ClL
<a href="/2ClL">[r]</a> <a href="/2ClL/">[h]</a>
@ Thu Oct 29 00:27:03 2020
</div>
</div>
<div class="t">
2ClK
<a href="/2ClK">[r]</a> <a href="/2ClK/">[h]</a>
@ Thu Oct 29 00:26:44 2020
</div>
</div>
<div class="t">
2ClJ
<a href="/2ClJ">[r]</a> <a href="/2ClJ/">[h]</a>
@ Thu Oct 29 00:26:25 2020
</div>
</div>
<div class="t">
2ClI
<a href="/2ClI">[r]</a> <a href="/2ClI/">[h]</a>
@ Thu Oct 29 00:26:05 2020
</div>
</div>
<div class="t">
2ClH
<a href="/2ClH">[r]</a> <a href="/2ClH/">[h]</a>
@ Thu Oct 29 00:16:21 2020
</div>
</div>
<div class="t">
2ClG
<a href="/2ClG">[r]</a> <a href="/2ClG/">[h]</a>
@ Thu Oct 29 00:16:07 2020
</div>
</div>
<div class="t">
2ClF
<a href="/2ClF">[r]</a> <a href="/2ClF/">[h]</a>
@ Thu Oct 29 00:00:14 2020
</div>
</div>
<div class="t">
2ClE
<a href="/2ClE">[r]</a> <a href="/2ClE/">[h]</a>
@ Thu Oct 29 00:00:07 2020
</div>
</div>
<div class="t">
2ClD
<a href="/2ClD">[r]</a> <a href="/2ClD/">[h]</a>
@ Wed Oct 28 23:56:36 2020
</div>
</div>
<div class="t">
2ClC
<a href="/2ClC">[r]</a> <a href="/2ClC/">[h]</a>
@ Wed Oct 28 23:54:07 2020
</div>
2ClB
<a href="/2ClB">[r]</a> <a href="/2ClB/">[h]</a>
@ Wed Oct 28 23:53:07 2020
</div>
2ClA
<a href="/2ClA">[r]</a> <a href="/2ClA/">[h]</a>
@ Wed Oct 28 23:51:55 2020
</div>
</div>
<div class="t">
2Clz
<a href="/2Clz">[r]</a> <a href="/2Clz/">[h]</a>
@ Wed Oct 28 23:50:24 2020
</div>
</div>
<div class="t">
2Cly
<a href="/2Cly">[r]</a> <a href="/2Cly/">[h]</a>
@ Wed Oct 28 23:44:58 2020
</div>
</div>
<div class="t">
2Clx
<a href="/2Clx">[r]</a> <a href="/2Clx/">[h]</a>
@ Wed Oct 28 23:40:54 2020
</div>
</div>
<div class="t">
2Clw
<a href="/2Clw">[r]</a> <a href="/2Clw/">[h]</a>
@ Wed Oct 28 23:40:13 2020
</div>
</div>
<div class="t">
2Clv
<a href="/2Clv">[r]</a> <a href="/2Clv/">[h]</a>
@ Wed Oct 28 23:38:37 2020
</div>
</div>
<div class="t">
2Clu
<a href="/2Clu">[r]</a> <a href="/2Clu/">[h]</a>
@ Wed Oct 28 23:37:22 2020
</div>
</div>
<div class="t">
2Clt
<a href="/2Clt">[r]</a> <a href="/2Clt/">[h]</a>
@ Wed Oct 28 23:31:22 2020
</div>
</div>
<div class="t">
2Cls
<a href="/2Cls">[r]</a> <a href="/2Cls/">[h]</a>
@ Wed Oct 28 23:30:27 2020
</div>
</div>
<div class="t">
2Clr
<a href="/2Clr">[r]</a> <a href="/2Clr/">[h]</a>
@ Wed Oct 28 23:25:57 2020
</div>
</div>
<div class="t">
2Clq
<a href="/2Clq">[r]</a> <a href="/2Clq/">[h]</a>
@ Wed Oct 28 23:25:24 2020
</div>
</div>
<div class="t">
2Clo
<a href="/2Clo">[r]</a> <a href="/2Clo/">[h]</a>
@ Wed Oct 28 23:07:09 2020
</div>
</div>
<div class="t">
2Cln
<a href="/2Cln">[r]</a> <a href="/2Cln/">[h]</a>
@ Wed Oct 28 23:05:48 2020
</div>
</div>
<div class="t">
2Clm
<a href="/2Clm">[r]</a> <a href="/2Clm/">[h]</a>
@ Wed Oct 28 23:02:16 2020
</div>
</div>
<div class="t">
2Cll
<a href="/2Cll">[r]</a> <a href="/2Cll/">[h]</a>
@ Wed Oct 28 23:00:14 2020
</div>
</div>
<div class="t">
2Clk
<a href="/2Clk">[r]</a> <a href="/2Clk/">[h]</a>
@ Wed Oct 28 23:00:07 2020
</div>
</div>
<div class="t">
2Clj
<a href="/2Clj">[r]</a> <a href="/2Clj/">[h]</a>
@ Wed Oct 28 22:35:28 2020
</div>
</div>
<div class="t">
2Cli
<a href="/2Cli">[r]</a> <a href="/2Cli/">[h]</a>
@ Wed Oct 28 22:32:50 2020
</div>
</div>
<div class="t">
2Clh
<a href="/2Clh">[r]</a> <a href="/2Clh/">[h]</a>
@ Wed Oct 28 22:27:14 2020
</div>
</div>
<div class="t">
2Clg
<a href="/2Clg">[r]</a> <a href="/2Clg/">[h]</a>
@ Wed Oct 28 22:16:44 2020
</div>
</div>
<div class="t">
2Clf
<a href="/2Clf">[r]</a> <a href="/2Clf/">[h]</a>
@ Wed Oct 28 22:15:30 2020
</div>
</div>
<div class="t">
2Cle
<a href="/2Cle">[r]</a> <a href="/2Cle/">[h]</a>
@ Wed Oct 28 22:14:18 2020
</div>
</div>
<div class="t">
2Cld
<a href="/2Cld">[r]</a> <a href="/2Cld/">[h]</a>
@ Wed Oct 28 22:13:33 2020
</div>
</div>
<div class="t">
2Clc
<a href="/2Clc">[r]</a> <a href="/2Clc/">[h]</a>
@ Wed Oct 28 22:11:11 2020
</div>
</div>
<div class="t">
2Clb
<a href="/2Clb">[r]</a> <a href="/2Clb/">[h]</a>
issue #15767 @ Wed Oct 28 22:09:53 2020
</div>
</div>
<div class="t">
2Cla
<a href="/2Cla">[r]</a> <a href="/2Cla/">[h]</a>
@ Wed Oct 28 22:08:25 2020
</div>
</div>
<div class="t">
2Cl9
<a href="/2Cl9">[r]</a> <a href="/2Cl9/">[h]</a>
@ Wed Oct 28 22:04:26 2020
</div>
</div>
<div class="t">
2Cl7
<a href="/2Cl7">[r]</a> <a href="/2Cl7/">[h]</a>
@ Wed Oct 28 22:00:23 2020
</div>
</div>
<div class="t">
2Cl6
<a href="/2Cl6">[r]</a> <a href="/2Cl6/">[h]</a>
@ Wed Oct 28 22:00:13 2020
</div>
</div>
<div class="t">
2Cl5
<a href="/2Cl5">[r]</a> <a href="/2Cl5/">[h]</a>
@ Wed Oct 28 22:00:09 2020
</div>
</div>
<div class="t">
2Cl4
<a href="/2Cl4">[r]</a> <a href="/2Cl4/">[h]</a>
@ Wed Oct 28 21:59:27 2020
</div>
</div>
<div class="t">
2Cl3
<a href="/2Cl3">[r]</a> <a href="/2Cl3/">[h]</a>
0001-DTS-sun8i-h2-plus-orangepi-zero-added-audio-codec.patch @ Wed Oct 28 21:58:51 2020
</div>
</div>
<div class="t">
2Cl2
<a href="/2Cl2">[r]</a> <a href="/2Cl2/">[h]</a>
@ Wed Oct 28 21:58:17 2020
</div>
</div>
<div class="t">
2Cl1
<a href="/2Cl1">[r]</a> <a href="/2Cl1/">[h]</a>
@ Wed Oct 28 21:56:42 2020
</div>
</div>
<div class="t">
</body>
'''


def test_page_items():
    site = IxDotIoSite(None)
    ids = [x['pid'] for x in site.get_data_for_page(test_data)]
    assert ids == [i for i in range(624031, 624134)]
