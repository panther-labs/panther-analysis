# pylint: disable=line-too-long
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
    "1.116.59.211",
    "1.14.17.89",
    "1.179.247.182",
    "1.209.249.188",
    "101.204.24.28",
    "101.35.154.34",
    "101.71.37.219",
    "101.71.37.47",
    "101.71.38.179",
    "101.71.38.231",
    "103.103.0.141",
    "103.103.0.142",
    "103.107.198.108",
    "103.107.198.109",
    "103.214.5.13",
    "103.232.137.187",
    "103.4.30.79",
    "103.90.239.209",
    "104.200.138.39",
    "104.244.72.115",
    "104.244.72.129",
    "104.244.72.7",
    "104.244.73.43",
    "104.244.74.211",
    "104.244.74.57",
    "104.244.75.74",
    "104.244.76.13",
    "104.244.76.170",
    "104.244.76.173",
    "104.244.77.235",
    "104.244.78.213",
    "104.244.79.6",
    "104.248.144.120",
    "107.189.1.160",
    "107.189.1.178",
    "107.189.10.137",
    "107.189.11.153",
    "107.189.12.135",
    "107.189.14.182",
    "107.189.14.76",
    "107.189.14.98",
    "107.189.28.84",
    "107.189.29.107",
    "107.189.29.41",
    "107.189.31.195",
    "107.189.31.241",
    "107.189.5.206",
    "107.189.6.166",
    "107.189.8.65",
    "109.237.96.124",
    "109.70.100.26",
    "109.70.100.27",
    "109.70.100.28",
    "109.70.100.34",
    "109.70.100.36",
    "109.70.150.139",
    "110.42.200.96",
    "111.193.180.158",
    "111.28.189.51",
    "112.74.185.158",
    "112.74.34.48",
    "112.74.52.90",
    "113.141.64.14",
    "113.98.224.68",
    "114.112.161.155",
    "115.151.228.146",
    "115.151.228.18",
    "115.151.228.64",
    "115.151.228.83",
    "115.151.228.92",
    "115.151.228.95",
    "115.151.229.14",
    "115.151.229.16",
    "115.151.229.27",
    "115.151.229.39",
    "116.24.67.213",
    "116.62.20.122",
    "116.89.189.19",
    "116.89.189.30",
    "117.192.11.154",
    "118.27.36.56",
    "119.28.91.153",
    "120.195.30.152",
    "120.211.140.116",
    "120.24.23.84",
    "121.36.213.142",
    "121.4.56.143",
    "121.5.113.11",
    "121.5.219.20",
    "122.155.174.180",
    "122.161.50.23",
    "122.161.53.44",
    "123.60.215.208",
    "124.224.87.11",
    "128.199.15.215",
    "128.199.222.221",
    "128.31.0.13",
    "131.100.148.7",
    "133.130.120.176",
    "133.18.201.195",
    "134.122.34.28",
    "134.209.24.42",
    "134.209.82.14",
    "134.56.204.191",
    "135.148.43.32",
    "137.184.102.82",
    "137.184.104.73",
    "137.184.106.119",
    "137.184.111.180",
    "137.184.28.58",
    "137.184.96.216",
    "137.184.98.176",
    "137.184.99.8",
    "138.197.106.234",
    "138.197.108.154",
    "138.197.167.229",
    "138.197.193.220",
    "138.197.216.230",
    "138.197.72.76",
    "138.197.9.239",
    "138.199.21.10",
    "138.199.21.9",
    "138.68.155.222",
    "138.68.167.19",
    "138.68.250.214",
    "139.28.218.132",
    "139.28.218.133",
    "139.28.218.134",
    "139.28.219.109",
    "139.28.219.110",
    "139.59.101.242",
    "139.59.103.254",
    "139.59.108.31",
    "139.59.163.74",
    "139.59.182.104",
    "139.59.188.119",
    "139.59.224.7",
    "139.59.8.39",
    "139.59.96.42",
    "139.59.97.205",
    "139.59.99.80",
    "140.246.171.141",
    "142.93.148.12",
    "142.93.151.166",
    "142.93.157.150",
    "142.93.34.250",
    "142.93.36.237",
    "143.110.221.204",
    "143.110.221.219",
    "143.198.180.150",
    "143.198.183.66",
    "143.198.32.72",
    "143.198.45.117",
    "143.244.184.81",
    "144.48.37.78",
    "145.220.24.19",
    "146.56.131.161",
    "146.56.148.181",
    "146.59.45.142",
    "146.70.75.21",
    "146.70.75.53",
    "146.70.75.54",
    "147.135.6.221",
    "147.182.131.229",
    "147.182.150.124",
    "147.182.154.100",
    "147.182.167.165",
    "147.182.169.254",
    "147.182.179.141",
    "147.182.187.229",
    "147.182.199.94",
    "147.182.213.12",
    "147.182.216.21",
    "147.182.219.9",
    "147.182.242.144",
    "147.182.242.241",
    "150.158.189.96",
    "151.115.60.113",
    "151.80.148.159",
    "154.65.28.250",
    "156.146.35.73",
    "157.230.32.67",
    "157.245.109.75",
    "157.245.129.50",
    "159.203.187.141",
    "159.203.45.181",
    "159.203.58.73",
    "159.223.42.182",
    "159.223.61.102",
    "159.223.81.193",
    "159.223.9.17",
    "159.48.55.216",
    "159.65.146.60",
    "159.65.155.208",
    "159.65.175.123",
    "159.65.189.107",
    "159.65.194.103",
    "159.65.3.102",
    "159.65.43.94",
    "159.65.58.66",
    "159.65.59.77",
    "159.89.113.255",
    "159.89.115.238",
    "159.89.122.19",
    "159.89.133.216",
    "159.89.146.147",
    "159.89.150.150",
    "159.89.154.102",
    "159.89.154.185",
    "159.89.154.64",
    "159.89.154.77",
    "159.89.180.119",
    "159.89.48.173",
    "159.89.85.91",
    "159.89.94.219",
    "160.238.38.196",
    "160.238.38.207",
    "160.238.38.212",
    "161.35.119.60",
    "161.35.155.230",
    "161.35.156.13",
    "161.97.138.227",
    "162.247.74.201",
    "162.247.74.202",
    "162.255.202.246",
    "164.52.53.163",
    "164.90.199.216",
    "164.92.254.33",
    "165.22.201.45",
    "165.22.213.246",
    "165.227.209.202",
    "165.227.239.108",
    "165.227.32.109",
    "165.227.37.189",
    "165.232.80.166",
    "165.232.80.22",
    "165.232.84.226",
    "165.232.84.228",
    "167.172.44.255",
    "167.172.94.250",
    "167.71.1.144",
    "167.71.13.196",
    "167.71.4.81",
    "167.99.164.160",
    "167.99.164.201",
    "167.99.172.213",
    "167.99.172.58",
    "167.99.172.99",
    "167.99.186.227",
    "167.99.204.151",
    "167.99.221.217",
    "167.99.221.249",
    "167.99.251.87",
    "167.99.36.245",
    "167.99.44.32",
    "167.99.88.151",
    "170.210.45.163",
    "171.221.235.43",
    "171.25.193.20",
    "171.25.193.25",
    "171.25.193.77",
    "171.25.193.78",
    "172.105.42.5",
    "172.106.17.218",
    "172.107.194.186",
    "172.111.48.30",
    "172.241.167.37",
    "172.245.14.50",
    "172.83.40.103",
    "173.234.27.143",
    "174.138.6.128",
    "175.6.210.66",
    "176.10.104.240",
    "176.10.99.200",
    "177.131.174.12",
    "177.185.117.129",
    "178.128.226.212",
    "178.128.229.113",
    "178.128.232.114",
    "178.17.171.102",
    "178.17.171.150",
    "178.17.174.14",
    "178.176.202.121",
    "178.176.203.190",
    "178.20.55.16",
    "178.239.167.180",
    "178.239.173.228",
    "178.62.23.146",
    "178.62.32.211",
    "178.62.61.47",
    "178.62.79.49",
    "179.43.187.138",
    "18.116.198.193",
    "18.27.197.252",
    "18.64.115.100",
    "180.149.231.196",
    "180.149.231.197",
    "180.149.231.245",
    "181.214.39.2",
    "182.253.160.196",
    "182.99.234.208",
    "182.99.246.106",
    "182.99.246.141",
    "182.99.246.172",
    "182.99.246.179",
    "182.99.246.183",
    "182.99.246.187",
    "182.99.246.199",
    "182.99.247.122",
    "182.99.247.145",
    "182.99.247.181",
    "182.99.247.188",
    "182.99.247.253",
    "182.99.247.67",
    "182.99.247.75",
    "185.10.68.168",
    "185.100.86.128",
    "185.100.87.202",
    "185.100.87.41",
    "185.107.47.171",
    "185.107.47.215",
    "185.107.70.56",
    "185.117.118.15",
    "185.129.61.1",
    "185.129.61.4",
    "185.130.44.108",
    "185.14.97.147",
    "185.165.168.77",
    "185.191.32.198",
    "185.199.100.233",
    "185.202.220.109",
    "185.202.220.75",
    "185.213.155.168",
    "185.216.74.114",
    "185.218.127.47",
    "185.220.100.240",
    "185.220.100.241",
    "185.220.100.242",
    "185.220.100.243",
    "185.220.100.244",
    "185.220.100.245",
    "185.220.100.246",
    "185.220.100.247",
    "185.220.100.248",
    "185.220.100.249",
    "185.220.100.250",
    "185.220.100.251",
    "185.220.100.252",
    "185.220.100.253",
    "185.220.100.254",
    "185.220.100.255",
    "185.220.101.129",
    "185.220.101.131",
    "185.220.101.132",
    "185.220.101.133",
    "185.220.101.134",
    "185.220.101.135",
    "185.220.101.136",
    "185.220.101.137",
    "185.220.101.138",
    "185.220.101.139",
    "185.220.101.140",
    "185.220.101.141",
    "185.220.101.142",
    "185.220.101.143",
    "185.220.101.144",
    "185.220.101.145",
    "185.220.101.146",
    "185.220.101.147",
    "185.220.101.148",
    "185.220.101.149",
    "185.220.101.150",
    "185.220.101.151",
    "185.220.101.152",
    "185.220.101.153",
    "185.220.101.154",
    "185.220.101.155",
    "185.220.101.156",
    "185.220.101.157",
    "185.220.101.158",
    "185.220.101.159",
    "185.220.101.160",
    "185.220.101.161",
    "185.220.101.162",
    "185.220.101.163",
    "185.220.101.164",
    "185.220.101.165",
    "185.220.101.167",
    "185.220.101.168",
    "185.220.101.169",
    "185.220.101.170",
    "185.220.101.171",
    "185.220.101.172",
    "185.220.101.173",
    "185.220.101.174",
    "185.220.101.175",
    "185.220.101.176",
    "185.220.101.177",
    "185.220.101.178",
    "185.220.101.179",
    "185.220.101.180",
    "185.220.101.181",
    "185.220.101.182",
    "185.220.101.183",
    "185.220.101.184",
    "185.220.101.185",
    "185.220.101.186",
    "185.220.101.187",
    "185.220.101.188",
    "185.220.101.189",
    "185.220.101.190",
    "185.220.101.191",
    "185.220.101.32",
    "185.220.101.33",
    "185.220.101.34",
    "185.220.101.35",
    "185.220.101.36",
    "185.220.101.37",
    "185.220.101.38",
    "185.220.101.39",
    "185.220.101.41",
    "185.220.101.42",
    "185.220.101.43",
    "185.220.101.44",
    "185.220.101.45",
    "185.220.101.46",
    "185.220.101.48",
    "185.220.101.49",
    "185.220.101.50",
    "185.220.101.51",
    "185.220.101.52",
    "185.220.101.53",
    "185.220.101.54",
    "185.220.101.55",
    "185.220.101.56",
    "185.220.101.57",
    "185.220.101.58",
    "185.220.101.60",
    "185.220.101.61",
    "185.220.101.62",
    "185.220.101.63",
    "185.220.102.241",
    "185.220.102.242",
    "185.220.102.246",
    "185.220.102.249",
    "185.220.102.250",
    "185.220.102.252",
    "185.220.102.253",
    "185.220.102.254",
    "185.220.102.7",
    "185.220.102.8",
    "185.220.103.116",
    "185.220.103.119",
    "185.220.103.4",
    "185.220.103.7",
    "185.232.23.46",
    "185.236.200.117",
    "185.244.214.217",
    "185.245.86.84",
    "185.245.86.86",
    "185.245.87.245",
    "185.250.148.157",
    "185.38.175.130",
    "185.38.175.131",
    "185.38.175.132",
    "185.4.132.183",
    "185.51.76.187",
    "185.56.80.65",
    "185.7.33.36",
    "185.83.214.69",
    "188.166.102.47",
    "188.166.105.150",
    "188.166.122.43",
    "188.166.170.135",
    "188.166.223.38",
    "188.166.225.104",
    "188.166.45.93",
    "188.166.48.55",
    "188.166.7.245",
    "188.166.74.97",
    "188.166.76.204",
    "188.166.86.206",
    "188.166.92.228",
    "188.241.156.221",
    "191.101.132.152",
    "191.232.38.25",
    "193.110.95.34",
    "193.189.100.195",
    "193.189.100.201",
    "193.189.100.203",
    "193.218.118.183",
    "193.218.118.231",
    "193.3.19.159",
    "193.31.24.154",
    "193.32.210.125",
    "193.32.210.182",
    "194.110.84.39",
    "194.110.84.93",
    "194.135.33.152",
    "194.163.163.20",
    "194.163.44.188",
    "194.163.45.31",
    "194.48.199.78",
    "195.123.247.209",
    "195.176.3.19",
    "195.176.3.23",
    "195.176.3.24",
    "195.19.192.26",
    "195.206.105.217",
    "195.251.41.139",
    "195.254.135.76",
    "195.54.160.149",
    "197.246.171.111",
    "197.246.171.83",
    "198.144.121.43",
    "198.98.51.189",
    "198.98.60.19",
    "199.195.250.77",
    "199.249.230.119",
    "20.205.104.227",
    "20.71.156.146",
    "203.27.106.142",
    "203.27.106.165",
    "204.8.156.142",
    "205.185.115.217",
    "205.185.117.149",
    "206.189.20.141",
    "207.180.202.75",
    "209.127.17.234",
    "209.127.17.242",
    "209.141.41.103",
    "209.141.45.189",
    "209.141.45.227",
    "209.141.58.146",
    "209.58.146.160",
    "209.97.147.103",
    "210.217.18.76",
    "211.154.194.21",
    "211.218.126.140",
    "212.102.50.103",
    "212.102.50.87",
    "212.102.50.89",
    "212.192.216.30",
    "212.192.246.95",
    "212.193.30.142",
    "212.193.57.225",
    "213.152.188.4",
    "213.202.216.189",
    "213.203.177.219",
    "217.112.83.246",
    "217.146.83.229",
    "218.29.217.234",
    "218.89.222.71",
    "221.199.187.100",
    "221.226.159.22",
    "221.228.87.37",
    "23.108.92.140",
    "23.120.182.121",
    "23.129.64.130",
    "23.129.64.131",
    "23.129.64.133",
    "23.129.64.134",
    "23.129.64.135",
    "23.129.64.138",
    "23.129.64.139",
    "23.129.64.141",
    "23.129.64.142",
    "23.129.64.144",
    "23.129.64.145",
    "23.129.64.146",
    "23.129.64.148",
    "23.154.177.2",
    "23.154.177.4",
    "23.154.177.7",
    "23.82.194.167",
    "23.82.194.168",
    "3.26.198.32",
    "31.42.186.101",
    "31.6.19.41",
    "34.124.226.216",
    "34.247.50.189",
    "35.170.71.122",
    "36.155.14.163",
    "36.227.164.189",
    "37.120.158.20",
    "37.120.158.22",
    "37.120.199.196",
    "37.120.203.182",
    "37.123.163.58",
    "37.187.122.82",
    "37.19.212.104",
    "37.19.212.88",
    "37.19.213.150",
    "39.102.236.51",
    "40.64.92.153",
    "40.64.92.157",
    "40.64.92.158",
    "40.64.92.159",
    "41.203.140.114",
    "42.192.17.155",
    "42.192.69.45",
    "42.193.8.97",
    "42.98.70.127",
    "45.12.134.108",
    "45.129.56.200",
    "45.13.104.179",
    "45.130.229.168",
    "45.137.21.9",
    "45.153.160.130",
    "45.153.160.131",
    "45.153.160.133",
    "45.153.160.134",
    "45.153.160.135",
    "45.153.160.136",
    "45.153.160.138",
    "45.153.160.139",
    "45.153.160.2",
    "45.154.255.147",
    "45.155.205.233",
    "45.248.77.142",
    "45.33.120.240",
    "45.64.75.134",
    "45.83.193.150",
    "45.83.64.1",
    "45.83.65.114",
    "45.83.67.27",
    "46.101.223.115",
    "46.105.95.220",
    "46.166.139.111",
    "46.182.21.248",
    "49.234.43.244",
    "49.234.81.169",
    "49.7.224.217",
    "5.101.145.41",
    "5.101.145.43",
    "5.135.141.139",
    "5.157.38.50",
    "5.181.235.45",
    "5.182.210.216",
    "5.199.143.202",
    "5.2.69.50",
    "5.22.208.77",
    "51.15.43.205",
    "51.15.76.60",
    "51.255.106.85",
    "51.77.52.216",
    "52.200.111.193",
    "52.231.93.116",
    "52.232.211.160",
    "52.232.211.163",
    "52.232.211.166",
    "52.232.211.167",
    "52.95.72.73",
    "54.173.99.121",
    "58.100.164.147",
    "60.31.180.149",
    "61.175.202.154",
    "61.178.32.114",
    "61.19.25.207",
    "62.102.148.68",
    "62.102.148.69",
    "62.171.142.3",
    "62.181.147.15",
    "62.210.130.250",
    "62.76.41.46",
    "64.113.32.29",
    "64.227.67.110",
    "66.220.242.222",
    "67.205.170.85",
    "67.207.93.79",
    "68.183.192.239",
    "68.183.198.247",
    "68.183.198.36",
    "68.183.207.73",
    "68.183.33.144",
    "68.183.35.171",
    "68.183.36.244",
    "68.183.37.10",
    "68.183.41.150",
    "68.183.44.143",
    "68.183.45.190",
    "68.79.17.59",
    "72.223.168.73",
    "78.110.164.45",
    "80.71.158.12",
    "81.17.18.59",
    "81.17.18.60",
    "81.17.18.61",
    "81.17.18.62",
    "81.6.43.167",
    "82.102.25.253",
    "82.102.31.170",
    "82.118.18.201",
    "82.221.131.71",
    "84.17.39.201",
    "84.17.42.118",
    "85.10.195.175",
    "86.106.103.29",
    "86.109.208.194",
    "88.80.20.86",
    "89.163.143.8",
    "89.163.154.91",
    "89.163.243.88",
    "89.163.252.230",
    "89.187.161.35",
    "89.187.162.98",
    "89.238.178.213",
    "89.249.63.3",
    "89.38.69.136",
    "89.38.69.99",
    "89.40.183.205",
    "91.203.5.146",
    "91.207.173.119",
    "91.207.174.157",
    "91.219.237.21",
    "91.245.81.65",
    "92.151.52.150",
    "92.223.89.187",
    "92.242.40.21",
    "93.189.42.8",
    "94.142.241.194",
    "94.230.208.147",
    "95.216.226.236",
    "45.155.205.233",
}


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
    ":${lower:",
    "${env:",
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
    """Makes a potential malicous domain not render as a domain in most systems

    :param domain: Original domain
    :return: Sanitized domain
    """
    return domain.replace(".", "[.]")
