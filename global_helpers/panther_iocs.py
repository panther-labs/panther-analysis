# pylint: disable=line-too-long

import panther_base_helpers

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

# Ref: CVE-2023-3094
# https://www.helpnetsecurity.com/2024/03/31/xz-backdoored-linux-affected-distros/g
XZ_AMIS = {
    "ami-08f974397021146fe",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0edfc5ccf045075e0",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0cdbbdaeecf641b07",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0ed13d14184c434b1",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-01641141ad4a74f91",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0b3bfb6a56c63396c",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0da8d53ccbc7bb06d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-04ac563c2573f7019",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-095c98047e5191a7b",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0c31e2163fa4490ac",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0c54e696e7e698155",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-07c4e32e9e89efb1c",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-ap-northeast-1-gp3-0 ap-northeast-1
    "ami-0f69f59236acd8fba",  # fedora-coreos-40.20240329.10.0-x86_64 ap-northeast-1
    "ami-068eb259340b27a4b",  # fedora-coreos-40.20240329.10.0-aarch64 ap-northeast-1
    "ami-0652e4768eb0787ad",  # fedora-coreos-40.20240331.1.0-x86_64 ap-northeast-1
    "ami-01e935b9f466f9ed7",  # fedora-coreos-40.20240331.1.0-aarch64 ap-northeast-1
    "ami-0132b73d6dd24733f",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-050ba8395805b8ce3",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0ffa2f4f661fe40a3",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0f78215de005e2641",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-09289d01066e9af27",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0cefecd8b408036eb",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-08c6e19a188604111",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0f8c513258e11202d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-086df47494fd5ecdb",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0d5e356a143ff6feb",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0266f46bdd78350b1",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0b80d17a7dc5b6c29",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-ap-northeast-2-gp3-0 ap-northeast-2
    "ami-0c940943407a19b23",  # fedora-coreos-40.20240331.1.0-x86_64 ap-northeast-2
    "ami-0a62170ee0a6cb00b",  # fedora-coreos-40.20240329.10.0-aarch64 ap-northeast-2
    "ami-03be7f3add5cd0dde",  # fedora-coreos-40.20240331.1.0-aarch64 ap-northeast-2
    "ami-070eb6616f8f9366e",  # fedora-coreos-40.20240329.10.0-x86_64 ap-northeast-2
    "ami-08a9fa97837000af2",  # fedora-coreos-40.20240329.10.0-aarch64 ap-northeast-3
    "ami-023f10e77fab380ea",  # fedora-coreos-40.20240329.10.0-x86_64 ap-northeast-3
    "ami-030641db3f3f075c6",  # fedora-coreos-40.20240331.1.0-aarch64 ap-northeast-3
    "ami-03a66b5f7d1f45f05",  # fedora-coreos-40.20240331.1.0-x86_64 ap-northeast-3
    "ami-018e5ec4c71a02563",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0d21816c5fed06222",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0650e95e10cddfe86",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0d8a3155917df9224",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-02cf1b782cbf8ce44",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-060d0a90cb0f2a3a8",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0fceb2aef87248b16",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0ee33a4d24da47c9e",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0de9d24a0a956d338",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-05f8c75683ae14a00",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-06cc320fb70dc3658",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0e5f7945e2c0a5b27",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-ap-south-1-gp3-0 ap-south-1
    "ami-0aab2290ead070285",  # fedora-coreos-40.20240331.1.0-aarch64 ap-south-1
    "ami-02ebbd07b85df07f3",  # fedora-coreos-40.20240329.10.0-x86_64 ap-south-1
    "ami-02ee14719e7c21275",  # fedora-coreos-40.20240329.10.0-aarch64 ap-south-1
    "ami-0eb8390d2255b2c7f",  # fedora-coreos-40.20240331.1.0-x86_64 ap-south-1
    "ami-02d7c61a4040c555f",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-05645c6a461e033c9",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-02186a7f6169122dc",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0c1585cbf5e73cc1e",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0429a7233e80586d2",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-01401ea8a15bf2503",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0fc2f877e0ef88ac5",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-014b02231fae70d7a",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0961f0908e7cbb5a0",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0bf5c819317a704d5",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0b5dcf0d23dd1cb78",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-071cd9ae3dd16663c",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-ap-southeast-1-gp3-0 ap-southeast-1
    "ami-0dbe71c2ce11d698c",  # fedora-coreos-40.20240329.10.0-aarch64 ap-southeast-1
    "ami-0b47f8ae2dc6d24f3",  # fedora-coreos-40.20240331.1.0-x86_64 ap-southeast-1
    "ami-02d20db09bf8e28c8",  # fedora-coreos-40.20240331.1.0-aarch64 ap-southeast-1
    "ami-03088bd1505f6ae5e",  # fedora-coreos-40.20240329.10.0-x86_64 ap-southeast-1
    "ami-035b1dafce72ac02e",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-075d106c120fb481e",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-0cb951277fde9f7d5",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-0f6b2a2847db753bf",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-0a9540e380446f382",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-08ca87171dbc818d7",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-0bfd0266b107b6955",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-03823c12b0e09a536",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-073e9f0b78425bdd6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-05c6820aed5b665a1",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-06aa465859abfe347",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-0fe7d9707e702a13e",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-ap-southeast-2-gp3-0 ap-southeast-2
    "ami-075cd46c0bc62d008",  # fedora-coreos-40.20240329.10.0-aarch64 ap-southeast-2
    "ami-0311d8c14d2a7035b",  # fedora-coreos-40.20240331.1.0-aarch64 ap-southeast-2
    "ami-09c0a5a1241b4fcce",  # fedora-coreos-40.20240329.10.0-x86_64 ap-southeast-2
    "ami-096b56b4de809cffe",  # fedora-coreos-40.20240331.1.0-x86_64 ap-southeast-2
    "ami-0db952d81e66ada95",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-01b1ee3368a31c994",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-06a2bcb91739e41f7",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0bbffb266d024e316",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0f73621d46081da00",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-095a6d44db6018054",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0dec58aca231a82e6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0ae607528e2f9391d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0a14647322af86be9",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0b41e3fde6356b76d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-0fe2626321b62790f",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-03f26b5a76090780d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-ca-central-1-gp3-0 ca-central-1
    "ami-04edae0331a2cb99a",  # fedora-coreos-40.20240331.1.0-x86_64 ca-central-1
    "ami-05d40c4aba79d696a",  # fedora-coreos-40.20240331.1.0-aarch64 ca-central-1
    "ami-018818658060cd185",  # fedora-coreos-40.20240329.10.0-aarch64 ca-central-1
    "ami-0a54e56d84fc1fde2",  # fedora-coreos-40.20240329.10.0-x86_64 ca-central-1
    "ami-0b0c6db4cee6ebbcb",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0011fd6bde84052e0",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0c633084aabd8fe9d",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-042e6b5eef13326c5",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0a6c3074e9ef5eb22",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-04bd19e31bbecfcd0",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0ac4df0e77d4dcd08",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0d7f3ea5e69f37cf6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-071fb6330ec75ed99",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-07cfa39d313b5bb1d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0f2d495891c81cda4",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-0b22caf7ce0715f3b",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-eu-central-1-gp3-0 eu-central-1
    "ami-03a0102e43619d36b",  # fedora-coreos-40.20240331.1.0-aarch64 eu-central-1
    "ami-06a49229bdd5273d9",  # fedora-coreos-40.20240331.1.0-x86_64 eu-central-1
    "ami-076d5c937d8f98c03",  # fedora-coreos-40.20240329.10.0-x86_64 eu-central-1
    "ami-0e194fcd036523ca4",  # fedora-coreos-40.20240329.10.0-aarch64 eu-central-1
    "ami-0679e33db04e369fc",  # fedora-coreos-40.20240331.1.0-x86_64 eu-north-1
    "ami-0d91dff508cea2dd3",  # fedora-coreos-40.20240329.10.0-aarch64 eu-north-1
    "ami-0d470a67462b1b4d6",  # fedora-coreos-40.20240329.10.0-x86_64 eu-north-1
    "ami-09e4f9084e0950377",  # fedora-coreos-40.20240331.1.0-aarch64 eu-north-1
    "ami-066d751b0a5cb9757",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-08d155e7d87534921",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-080ad449e81c53a5d",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0c7c0ab709d094e65",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0a5e7b1fd76745847",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0ae45404264806116",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-028dc6f7c33ee0b4d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-08e011719a44ec4d6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-05656a908af9df8a6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0c57ab4f2937cf855",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0add1262f7a3bb815",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0a1f87dd2bc94bbfc",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-eu-west-1-gp3-0 eu-west-1
    "ami-0107d7e090bded724",  # fedora-coreos-40.20240329.10.0-aarch64 eu-west-1
    "ami-037402d3e5225050f",  # fedora-coreos-40.20240331.1.0-x86_64 eu-west-1
    "ami-02cd531f57b79a7aa",  # fedora-coreos-40.20240331.1.0-aarch64 eu-west-1
    "ami-0d128112cb2749e7a",  # fedora-coreos-40.20240329.10.0-x86_64 eu-west-1
    "ami-04f3a958a99290dbe",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0b64bc38f7b8cd696",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-056f52f9d0798067d",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0fd8a21ebe9ece144",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-019718d1b66fea681",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0d6a98836104061a6",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0836d1ee2596846e8",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0ea6a963b5b01b89f",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-068fb00a122c8a3ae",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0392afabc5da9aa27",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-03fbe24ada996c761",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-0d157bb01a2c80b71",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-eu-west-2-gp3-0 eu-west-2
    "ami-031a77879f974be22",  # fedora-coreos-40.20240329.10.0-aarch64 eu-west-2
    "ami-0eab39cbbd3b450b0",  # fedora-coreos-40.20240331.1.0-aarch64 eu-west-2
    "ami-0de5e6511774e513c",  # fedora-coreos-40.20240331.1.0-x86_64 eu-west-2
    "ami-014a2387605b6ed3d",  # fedora-coreos-40.20240329.10.0-x86_64 eu-west-2
    "ami-099145a1f43770cd0",  # fedora-coreos-40.20240331.1.0-x86_64 eu-west-3
    "ami-01c5e7f50df21f6c7",  # fedora-coreos-40.20240329.10.0-x86_64 eu-west-3
    "ami-03a156814633590b1",  # fedora-coreos-40.20240329.10.0-aarch64 eu-west-3
    "ami-0ecfc4d55df8e9cc8",  # fedora-coreos-40.20240331.1.0-aarch64 eu-west-3
    "ami-0026b58ba1ae7e8fc",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-048e80bf078f16fb9",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-05f7ef4f69d6a19c6",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-07ba6b69b4e8edecf",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-0f830b84842789ca4",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-0b02dbcea77692098",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-0f004fcf16b59f696",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-071cb491ffbb72a4c",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-005e533a8828c40a7",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-00d903771c231f51b",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-007347abb797443e9",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-0c51bef7879a63e99",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-sa-east-1-gp3-0 sa-east-1
    "ami-02e51dd313c554c1d",  # fedora-coreos-40.20240329.10.0-aarch64 sa-east-1
    "ami-0e37c7770d63c3020",  # fedora-coreos-40.20240329.10.0-x86_64 sa-east-1
    "ami-0f527f9fbe07448f5",  # fedora-coreos-40.20240331.1.0-aarch64 sa-east-1
    "ami-0a0a0f1c36cf8c3d7",  # fedora-coreos-40.20240331.1.0-x86_64 sa-east-1
    "ami-0b890d61c6bfc7fd0",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-099c0415ae1c8704f",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-01d93f2ed9036c444",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-03f31087fc159f228",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-05693d19b77ccc629",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-us-east-1-gp3-0 us-east-1
    "ami-0f4eefe7bf5636f18",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-0c3899a500d3f81d9",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-078715005abc0bea3",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-059e900e520a0febe",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-0e399bd567fbd4050",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-us-east-1-gp3-0 us-east-1
    "ami-01d556a8aed949865",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-028ae719081ff9141",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-us-east-1-gp3-0 us-east-1
    "ami-0fc4ac1cc421c274f",  # fedora-coreos-40.20240328.10.1-aarch64 us-east-1
    "ami-0e8c9542806a49fdc",  # fedora-coreos-40.20240326.10.0-aarch64 us-east-1
    "ami-03cebfaac4a4b6156",  # fedora-coreos-40.20240328.10.0-x86_64 us-east-1
    "ami-08f1ca38230424149",  # fedora-coreos-40.20240331.10.0-x86_64 us-east-1
    "ami-08e57ea8f8ecbb96b",  # fedora-coreos-40.20240330.10.0-aarch64 us-east-1
    "ami-0420fa82d1a55a04d",  # fedora-coreos-40.20240331.10.0-aarch64 us-east-1
    "ami-0d8cd73663a3180e4",  # fedora-coreos-40.20240328.10.0-aarch64 us-east-1
    "ami-0e172c40c3ab0283b",  # fedora-coreos-40.20240328.10.3-x86_64 us-east-1
    "ami-02a5da3b3c653541c",  # fedora-coreos-40.20240328.10.1-x86_64 us-east-1
    "ami-0d6b046b67f2ec40c",  # fedora-coreos-40.20240331.1.0-x86_64 us-east-1
    "ami-0ded444bcb8def0a0",  # fedora-coreos-40.20240326.10.1-x86_64 us-east-1
    "ami-0226592a906bae601",  # fedora-coreos-40.20240326.10.1-aarch64 us-east-1
    "ami-087e9a07cbe450b1f",  # fedora-coreos-40.20240331.10.1-x86_64 us-east-1
    "ami-00f5623d1d8d863aa",  # fedora-coreos-40.20240331.1.0-aarch64 us-east-1
    "ami-0b041ca5b98d2314a",  # fedora-coreos-40.20240329.10.0-aarch64 us-east-1
    "ami-011ccf5cf6aca3e39",  # fedora-coreos-40.20240328.10.3-aarch64 us-east-1
    "ami-098ca38fb3622c1d2",  # fedora-coreos-40.20240326.10.0-x86_64 us-east-1
    "ami-0ac1330dadf281b2f",  # fedora-coreos-40.20240328.10.2-x86_64 us-east-1
    "ami-062c38d59d67dcd81",  # fedora-coreos-40.20240330.10.0-x86_64 us-east-1
    "ami-09322b0a6edb8b311",  # fedora-coreos-40.20240329.10.0-x86_64 us-east-1
    "ami-0d561945ea877a79d",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-098324e931c6b5447",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-0f2b057ecde88941c",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-04096bec7d888ed10",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-0dec4ce2229937c36",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-us-east-2-gp3-0 us-east-2
    "ami-0c69ad03c8495ad63",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-03faf8bbf92792d9b",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-0e409c60b98ea8358",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-0d98bb4012dd4d082",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-073de5a3532e0cafb",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-us-east-2-gp3-0 us-east-2
    "ami-01da3df628ddfeb94",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-05f2d9411b6cf8ba3",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-us-east-2-gp3-0 us-east-2
    "ami-009ea87b9afa8b27e",  # fedora-coreos-40.20240329.10.0-aarch64 us-east-2
    "ami-0b19c3ec448c2db5d",  # fedora-coreos-40.20240329.10.0-x86_64 us-east-2
    "ami-0da567111c7144af3",  # fedora-coreos-40.20240331.1.0-x86_64 us-east-2
    "ami-0270bd5d45ef1ce2f",  # fedora-coreos-40.20240331.1.0-aarch64 us-east-2
    "ami-0c2074bb1d42d5c47",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-02870e3c3ac06f22a",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-011d5d2e4edd5f115",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-us-west-1-gp3-0 us-west-1
    "ami-04faeff5f8a080464",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-01b2d9b3409a192f4",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-0eea7d6b69d96ffd0",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-05dc988900937cdb6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-0d2ad965cc77d1efc",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-us-west-1-gp3-0 us-west-1
    "ami-0bb8b68a73943c9fb",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-0051b0d7b66151c83",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-0b854f86a33caa37d",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-034644ca75beb9ba2",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-us-west-1-gp3-0 us-west-1
    "ami-0925bf6e49075aa8c",  # fedora-coreos-40.20240331.1.0-aarch64 us-west-1
    "ami-0ddda0b5b83d56208",  # fedora-coreos-40.20240329.10.0-aarch64 us-west-1
    "ami-03790d65f69cf2e00",  # fedora-coreos-40.20240331.1.0-x86_64 us-west-1
    "ami-049e91e7496138039",  # fedora-coreos-40.20240329.10.0-x86_64 us-west-1
    "ami-03ba5852acf89c4be",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.1-hvm-us-west-2-gp3-0 us-west-2
    "ami-08c6b132407b025b7",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240401.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-036645f0339f5a889",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240331.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-020a359780bc6f835",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240330.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-092e3b17e435e5e58",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240328.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-03cad1daf37200a2d",  # Fedora-Cloud-Base-AmazonEC2.x86_64-Rawhide-20240329.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-0500458bbdc480fd9",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.1-hvm-us-west-2-gp3-0 us-west-2
    "ami-0ad79a6b913a454e5",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240330.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-09f2d28702f57b85c",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240328.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-08200843b835932e6",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240331.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-07032d2bce4208ea2",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240401.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-0af17f237fcd582cd",  # Fedora-Cloud-Base-AmazonEC2.aarch64-Rawhide-20240329.n.0-hvm-us-west-2-gp3-0 us-west-2
    "ami-0c674423dd90e483c",  # fedora-coreos-40.20240329.10.0-x86_64 us-west-2
    "ami-0e4711bf3d106e149",  # fedora-coreos-40.20240331.1.0-aarch64 us-west-2
    "ami-09b81f0f9f2acfcdf",  # fedora-coreos-40.20240331.1.0-x86_64 us-west-2
    "ami-083bb1ae22e9bf463",  # fedora-coreos-40.20240329.10.0-aarch64 us-west-2
}


def ioc_match(indicators: list, known_iocs: set) -> list:
    """Global `ioc_match` is DEPRECATED.
    Instead, use `from panther_base_helpers import ioc_match`."""
    return panther_base_helpers.ioc_match(indicators, known_iocs)


def sanitize_domain(domain: str) -> str:
    """Global `sanitize_domain` is DEPRECATED.
    Instead, use `from panther_base_helpers import defang_ioc`."""
    return panther_base_helpers.defang_ioc(domain)
