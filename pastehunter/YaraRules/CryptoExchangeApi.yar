rule CryptoExchangeApi
{
    meta:
        description = "Contains Crypro Exchange API URL"
        author = "Jason Schorr (0xBanana)"
        source = "https://github.com/cryptodefense/PasteHunter-Yara/blob/master/CryptoExchangeApi.yar"
    strings:
    	$a = "api.binance.com" nocase wide ascii
		$a0 = "1btcxe.com/api" nocase wide ascii
		$a1 = "acx.io/api" nocase wide ascii
		$a2 = "anxpro.com/api" nocase wide ascii
		$a3 = "anybits.com/api" nocase wide ascii
		$a4 = "www.bcex.top" nocase wide ascii
		$a5 = "api.bibox.com" nocase wide ascii
		$a6 = "bit2c.co.il" nocase wide ascii
		$a7 = "api.bitfinex.com" nocase wide ascii
		$a8 = "api.bitfinex.com" nocase wide ascii
		$a9 = "api.bitflyer.jp" nocase wide ascii
		$aa = "api.bitforex.com" nocase wide ascii
		$ab = "bitibu.com" nocase wide ascii
		$ac = "bitlish.com/api" nocase wide ascii
		$ad = "www.bitmex.com" nocase wide ascii
		$ae = "bitsane.com/api" nocase wide ascii
		$af = "api.bitso.com" nocase wide ascii
		$ag = "www.bitstamp.net/api" nocase wide ascii
		$ah = "www.bitstamp.net/api" nocase wide ascii
		$ai = "api.bl3p.eu" nocase wide ascii
		$aj = "braziliex.com/api/v1" nocase wide ascii
		$ak = "btc-alpha.com/api" nocase wide ascii
		$al = "www.btcbox.co.jp/api" nocase wide ascii
		$am = "www.btcexchange.ph/api" nocase wide ascii
		$an = "btc-trade.com.ua/api" nocase wide ascii
		$ao = "www.btcturk.com/api" nocase wide ascii
		$ap = "www.buda.com/api" nocase wide ascii
		$aq = "bx.in.th/api" nocase wide ascii
		$ar = "cex.io/api" nocase wide ascii
		$as = "api.cobinhood.com" nocase wide ascii
		$at = "api.coinbase.com" nocase wide ascii
		$au = "api.prime.coinbase.com" nocase wide ascii
		$av = "api.pro.coinbase.com" nocase wide ascii
		$aw = "coincheck.com/api" nocase wide ascii
		$ax = "www.coinexchange.io/api/v1" nocase wide ascii
		$ay = "coinfalcon.com" nocase wide ascii
		$az = "webapi.coinfloor.co.uk:8090/bist" nocase wide ascii
		$aa1 = "coinmate.io/api" nocase wide ascii
		$aa2 = "api.coinone.co.kr" nocase wide ascii
		$aa3 = "api.crex24.com" nocase wide ascii
		$aa4 = "api.cryptonbtc.com" nocase wide ascii
		$aa5 = "www.deribit.com" nocase wide ascii
		$aa6 = "api.ethfinex.com" nocase wide ascii
		$aa7 = "api.fcoin.com" nocase wide ascii
		$aa8 = "api.flowbtc.com:8405/ajax" nocase wide ascii
		$aa9 = "www.fybse.se/api/SEK" nocase wide ascii
		$aa0 = "www.fybsg.com/api/SGD" nocase wide ascii
		$aab = "api.gatecoin.com" nocase wide ascii
		$aac = "api.gdax.com" nocase wide ascii
		$aad = "api.gemini.com" nocase wide ascii
		$aae = "getbtc.org/api" nocase wide ascii
		$aaf = "api.hitbtc.com" nocase wide ascii
		$aag = "api.hitbtc.com" nocase wide ascii
		$aah = "api.huobi.com" nocase wide ascii
		$aai = "ice3x.com/api" nocase wide ascii
		$aaj = "api.itbit.com" nocase wide ascii
		$aak = "www.jubi.com/api" nocase wide ascii
		$aal = "kuna.io" nocase wide ascii
		$aam = "api.lakebtc.com" nocase wide ascii
		$aan = "api.lbank.info" nocase wide ascii
		$aao = "api.liquid.com" nocase wide ascii
		$aap = "api.livecoin.net" nocase wide ascii
		$aaq = "api.mybitx.com/api" nocase wide ascii
		$aar = "mixcoins.com/api" nocase wide ascii
		$aas = "novaexchange.com/remote" nocase wide ascii
		$aat = "paymium.com/api" nocase wide ascii
		$aau = "api.quadrigacx.com" nocase wide ascii
		$aav = "www.rightbtc.com/api" nocase wide ascii
		$aaw = "www.southxchange.com/api" nocase wide ascii
		$aax = "api.theocean.trade/api" nocase wide ascii
		$aay = "api.therocktrading.com" nocase wide ascii
		$aaz = "www.tidebit.com" nocase wide ascii
		$ba = "open-api.uex.com/open/api" nocase wide ascii
		$bb = "api.vaultoro.com" nocase wide ascii
		$bc = "cryptottlivewebapi.xbtce.net:8443/api" nocase wide ascii
		$bd = "yunbi.com" nocase wide ascii
		$be = "api.zaif.jp" nocase wide ascii

    condition:
       any of them
}