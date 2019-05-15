function FindProxyForURL(url, host) {
   host_ip = myIpAddress();
   resolved_IP = dnsResolve(host);

/* O365 Express Route ACCESS groups */
        if      (isInNet(resolved_IP, "13.65.240.22", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.66.58.59", "255.255.255.255")     ||
                 isInNet(resolved_IP, "13.70.156.206", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.71.145.114", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.71.145.122", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.71.151.88", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.75.149.223", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.78.120.69", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.78.120.70", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.78.120.99", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.78.122.54", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.80.22.71", "255.255.255.255")     ||
                 isInNet(resolved_IP, "13.80.125.22", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.84.178.101", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.84.216.209", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.84.219.100", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.84.222.249", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.87.36.128", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.88.17.54", "255.255.255.255")     ||
                 isInNet(resolved_IP, "13.91.91.243", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.92.181.66", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.92.236.241", "255.255.255.255")   ||
                 isInNet(resolved_IP, "13.93.164.45", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.95.29.177", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.95.30.46", "255.255.255.255")     ||
                 isInNet(resolved_IP, "13.107.6.156", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.7.190", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.9.156", "255.255.255.254")    ||
                 isInNet(resolved_IP, "23.96.32.105", "255.255.255.255")    ||
                 isInNet(resolved_IP, "23.96.251.50", "255.255.255.255")    ||
                 isInNet(resolved_IP, "23.96.253.65", "255.255.255.255")    ||
                 isInNet(resolved_IP, "23.97.66.55", "255.255.255.255")     ||
                 isInNet(resolved_IP, "23.97.78.94", "255.255.255.255")     ||
                 isInNet(resolved_IP, "23.99.121.16", "255.255.255.255")    ||
                 isInNet(resolved_IP, "23.99.125.4", "255.255.255.255")     ||
                 isInNet(resolved_IP, "40.69.185.117", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.71.88.196", "255.255.255.255")    ||
                 isInNet(resolved_IP, "40.76.54.117", "255.255.255.255")    ||
                 isInNet(resolved_IP, "40.83.120.174", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.83.127.89", "255.255.255.255")    ||
                 isInNet(resolved_IP, "40.83.185.155", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.83.185.230", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.84.145.72", "255.255.255.255")    ||
                 isInNet(resolved_IP, "40.112.144.173", "255.255.255.255")  ||
                 isInNet(resolved_IP, "40.112.187.89", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.113.91.234", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.117.96.104", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.117.100.187", "255.255.255.255")  ||
                 isInNet(resolved_IP, "40.117.229.133", "255.255.255.255")  ||
                 isInNet(resolved_IP, "40.117.229.194", "255.255.255.255")  ||
                 isInNet(resolved_IP, "40.124.8.53", "255.255.255.255")     ||
                 isInNet(resolved_IP, "51.140.45.81", "255.255.255.255")    ||
                 isInNet(resolved_IP, "51.140.226.217", "255.255.255.255")  ||
                 isInNet(resolved_IP, "51.142.213.184", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.163.58.153", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.163.93.38", "255.255.255.255")    ||
                 isInNet(resolved_IP, "52.164.121.65", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.164.124.124", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.164.127.6", "255.255.255.255")    ||
                 isInNet(resolved_IP, "52.168.128.89", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.172.49.206", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.174.56.180", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.175.154.183", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.175.158.8", "255.255.255.255")    ||
                 isInNet(resolved_IP, "52.178.27.129", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.178.144.25", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.178.146.3", "255.255.255.255")    ||
                 isInNet(resolved_IP, "52.178.146.67", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.178.150.186", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.183.75.62", "255.255.255.255")    ||
                 isInNet(resolved_IP, "52.185.154.106", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.187.42.197", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.187.78.144", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.225.223.43", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.228.36.141", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.230.24.83", "255.255.255.255")    ||
                 isInNet(resolved_IP, "52.231.24.115", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.231.204.153", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.232.112.133", "255.255.255.255")  ||
                 isInNet(resolved_IP, "52.232.118.68", "255.255.255.255")   ||
                 isInNet(resolved_IP, "52.232.129.232", "255.255.255.255")  ||
                 isInNet(resolved_IP, "65.52.144.46", "255.255.255.255")    ||
                 isInNet(resolved_IP, "65.52.176.186", "255.255.255.255")   ||
                 isInNet(resolved_IP, "65.52.192.203", "255.255.255.255")   ||
                 isInNet(resolved_IP, "65.52.220.46", "255.255.255.255")    ||
                 isInNet(resolved_IP, "65.52.240.200", "255.255.255.255")   ||
                 isInNet(resolved_IP, "65.55.239.168", "255.255.255.255")   ||
                 isInNet(resolved_IP, "70.37.96.155", "255.255.255.255")    ||
                 isInNet(resolved_IP, "94.245.88.28", "255.255.255.255")    ||
                 isInNet(resolved_IP, "94.245.117.53", "255.255.255.255")   ||
                 isInNet(resolved_IP, "104.40.178.127", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.40.179.160", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.40.211.46", "255.255.255.255")   ||
                 isInNet(resolved_IP, "104.42.225.143", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.42.230.91", "255.255.255.255")   ||
                 isInNet(resolved_IP, "104.43.21.58", "255.255.255.255")    ||
                 isInNet(resolved_IP, "104.45.225.7", "255.255.255.255")    ||
                 isInNet(resolved_IP, "104.47.156.62", "255.255.255.255")   ||
                 isInNet(resolved_IP, "104.211.160.244", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.214.107.57", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.214.144.62", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.214.144.252", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.214.145.126", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.214.145.173", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.214.146.199", "255.255.255.255") ||
                 isInNet(resolved_IP, "111.221.96.149", "255.255.255.255")  ||
                 isInNet(resolved_IP, "111.221.104.43", "255.255.255.255")  ||
                 isInNet(resolved_IP, "137.116.156.3", "255.255.255.255")   ||
                 isInNet(resolved_IP, "137.116.248.150", "255.255.255.255") ||
                 isInNet(resolved_IP, "137.117.17.124", "255.255.255.255")  ||
                 isInNet(resolved_IP, "138.91.61.107", "255.255.255.255")   ||
                 isInNet(resolved_IP, "157.55.139.177", "255.255.255.255")  ||
                 isInNet(resolved_IP, "157.55.145.0", "255.255.255.128")    ||
                 isInNet(resolved_IP, "157.55.155.0", "255.255.255.128")    ||
                 isInNet(resolved_IP, "157.55.212.37", "255.255.255.255")   ||
                 isInNet(resolved_IP, "157.55.227.192", "255.255.255.192")  ||
                 isInNet(resolved_IP, "168.61.149.234", "255.255.255.255")  ||
                 isInNet(resolved_IP, "168.62.104.83", "255.255.255.255")   ||
                 isInNet(resolved_IP, "168.62.106.224", "255.255.255.255")  ||
                 isInNet(resolved_IP, "168.63.92.133", "255.255.255.255")   ||
                 isInNet(resolved_IP, "191.235.95.142", "255.255.255.255")  ||
                 isInNet(resolved_IP, "191.238.160.173", "255.255.255.255") ||
                 isInNet(resolved_IP, "207.46.73.250", "255.255.255.255")   ||
                 isInNet(resolved_IP, "207.46.140.244", "255.255.255.255")  ||
                 isInNet(resolved_IP, "207.46.141.38", "255.255.255.255")   ||
                 isInNet(resolved_IP, "207.46.156.124", "255.255.255.255")  ||
                 isInNet(resolved_IP, "207.46.216.54", "255.255.255.255")   ||
                 isInNet(resolved_IP, "213.199.128.119", "255.255.255.255") ||
                 isInNet(resolved_IP, "13.107.6.152", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.9.152", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.18.10", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.19.10", "255.255.255.254")    ||
                 isInNet(resolved_IP, "23.103.160.0", "255.255.240.0")      ||
                 isInNet(resolved_IP, "23.103.224.0", "255.255.224.0")      ||
                 isInNet(resolved_IP, "40.96.0.0", "255.248.0.0")           ||
                 isInNet(resolved_IP, "40.104.0.0", "255.254.0.0")          ||
                 isInNet(resolved_IP, "52.96.0.0", "255.252.0.0")           ||
                 isInNet(resolved_IP, "70.37.151.128", "255.255.255.128")   ||
                 isInNet(resolved_IP, "111.221.112.0", "255.255.248.0")     ||
                 isInNet(resolved_IP, "131.253.33.215", "255.255.255.255")  ||
                 isInNet(resolved_IP, "132.245.0.0", "255.255.0.0")         ||
                 isInNet(resolved_IP, "134.170.68.0", "255.255.254.0")      ||
                 isInNet(resolved_IP, "157.56.96.16", "255.255.255.240")    ||
                 isInNet(resolved_IP, "157.56.96.224", "255.255.255.240")   ||
                 isInNet(resolved_IP, "157.56.106.128", "255.255.255.240")  ||
                 isInNet(resolved_IP, "157.56.232.0", "255.255.248.0")      ||
                 isInNet(resolved_IP, "157.56.240.0", "255.255.240.0")      ||
                 isInNet(resolved_IP, "191.232.96.0", "255.255.224.0")      ||
                 isInNet(resolved_IP, "191.234.6.152", "255.255.255.255")   ||
                 isInNet(resolved_IP, "191.234.140.0", "255.255.252.0")     ||
                 isInNet(resolved_IP, "191.234.224.0", "255.255.252.0")     ||
                 isInNet(resolved_IP, "204.79.197.215", "255.255.255.255")  ||
                 isInNet(resolved_IP, "206.191.224.0", "255.255.224.0")     ||
                 isInNet(resolved_IP, "207.46.150.128", "255.255.255.128")  ||
                 isInNet(resolved_IP, "207.46.203.128", "255.255.255.192")  ||
                 isInNet(resolved_IP, "13.67.50.224", "255.255.255.248")    ||
                 isInNet(resolved_IP, "13.71.201.64", "255.255.255.192")    ||
                 isInNet(resolved_IP, "13.106.4.128", "255.255.255.128")    ||
                 isInNet(resolved_IP, "13.75.48.16", "255.255.255.248")     ||
                 isInNet(resolved_IP, "13.75.80.16", "255.255.255.248")     ||
                 isInNet(resolved_IP, "13.106.56.0", "255.255.255.128")     ||
                 isInNet(resolved_IP, "20.190.128.0", "255.255.192.0")      ||
                 isInNet(resolved_IP, "23.100.16.168", "255.255.255.248")   ||
                 isInNet(resolved_IP, "23.100.32.136", "255.255.255.248")   ||
                 isInNet(resolved_IP, "23.100.64.24", "255.255.255.248")    ||
                 isInNet(resolved_IP, "23.100.72.32", "255.255.255.248")    ||
                 isInNet(resolved_IP, "23.100.80.64", "255.255.255.248")    ||
                 isInNet(resolved_IP, "23.100.88.32", "255.255.255.248")    ||
                 isInNet(resolved_IP, "23.100.101.112", "255.255.255.240")  ||
                 isInNet(resolved_IP, "23.100.104.16", "255.255.255.240")   ||
                 isInNet(resolved_IP, "23.100.112.64", "255.255.255.248")   ||
                 isInNet(resolved_IP, "23.100.120.64", "255.255.255.248")   ||
                 isInNet(resolved_IP, "23.101.5.104", "255.255.255.248")    ||
                 isInNet(resolved_IP, "23.101.144.136", "255.255.255.248")  ||
                 isInNet(resolved_IP, "23.101.165.168", "255.255.255.248")  ||
                 isInNet(resolved_IP, "23.101.181.128", "255.255.255.248")  ||
                 isInNet(resolved_IP, "23.101.210.24", "255.255.255.248")   ||
                 isInNet(resolved_IP, "23.101.222.240", "255.255.255.240")  ||
                 isInNet(resolved_IP, "23.101.224.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "23.101.226.16", "255.255.255.240")   ||
                 isInNet(resolved_IP, "40.112.64.16", "255.255.255.240")    ||
                 isInNet(resolved_IP, "40.113.192.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "40.114.120.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "40.115.152.16", "255.255.255.240")   ||
                 isInNet(resolved_IP, "40.127.67.24", "255.255.255.248")    ||
                 isInNet(resolved_IP, "40.126.0.0", "255.255.192.0")        ||
                 isInNet(resolved_IP, "52.125.0.0", "255.255.128.0")        ||
                 isInNet(resolved_IP, "52.172.144.16", "255.255.255.240")   ||
                 isInNet(resolved_IP, "65.52.1.16", "255.255.255.248")      ||
                 isInNet(resolved_IP, "65.52.193.136", "255.255.255.248")   ||
                 isInNet(resolved_IP, "65.54.170.128", "255.255.255.128")   ||
                 isInNet(resolved_IP, "70.37.128.0", "255.255.254.0")       ||
                 isInNet(resolved_IP, "104.40.240.48", "255.255.255.240")   ||
                 isInNet(resolved_IP, "104.41.13.120", "255.255.255.248")   ||
                 isInNet(resolved_IP, "104.41.216.16", "255.255.255.240")   ||
                 isInNet(resolved_IP, "104.42.72.16", "255.255.255.248")    ||
                 isInNet(resolved_IP, "104.43.208.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "104.43.240.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "104.44.218.128", "255.255.255.128")  ||
                 isInNet(resolved_IP, "104.44.254.128", "255.255.255.128")  ||
                 isInNet(resolved_IP, "104.44.255.0", "255.255.255.128")    ||
                 isInNet(resolved_IP, "104.45.0.16", "255.255.255.240")     ||
                 isInNet(resolved_IP, "104.45.208.104", "255.255.255.248")  ||
                 isInNet(resolved_IP, "104.46.112.8", "255.255.255.248")    ||
                 isInNet(resolved_IP, "104.46.224.64", "255.255.255.240")   ||
                 isInNet(resolved_IP, "104.209.144.16", "255.255.255.248")  ||
                 isInNet(resolved_IP, "104.210.48.8", "255.255.255.248")    ||
                 isInNet(resolved_IP, "104.210.83.160", "255.255.255.248")  ||
                 isInNet(resolved_IP, "104.210.208.16", "255.255.255.248")  ||
                 isInNet(resolved_IP, "104.211.16.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "104.211.48.16", "255.255.255.248")   ||
                 isInNet(resolved_IP, "104.211.88.16", "255.255.255.240")   ||
                 isInNet(resolved_IP, "104.211.98.138", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.211.98.146", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.211.98.246", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.211.99.236", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.211.100.160", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.100.204", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.102.225", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.152.32", "255.255.255.224")  ||
                 isInNet(resolved_IP, "104.211.161.150", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.161.165", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.161.185", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.162.33", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.211.165.35", "255.255.255.255")  ||
                 isInNet(resolved_IP, "104.211.166.139", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.216.32", "255.255.255.224")  ||
                 isInNet(resolved_IP, "104.211.224.118", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.225.135", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.227.110", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.231.147", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.211.231.248", "255.255.255.255") ||
                 isInNet(resolved_IP, "104.215.96.24", "255.255.255.248")   ||
                 isInNet(resolved_IP, "104.215.144.64", "255.255.255.248")  ||
                 isInNet(resolved_IP, "104.215.184.16", "255.255.255.248")  ||
                 isInNet(resolved_IP, "131.253.120.128", "255.255.255.255") ||
                 isInNet(resolved_IP, "132.245.165.0", "255.255.255.128")   ||
                 isInNet(resolved_IP, "134.170.67.0", "255.255.255.128")    ||
                 isInNet(resolved_IP, "134.170.172.128", "255.255.255.128") ||
                 isInNet(resolved_IP, "157.55.45.128", "255.255.255.128")   ||
                 isInNet(resolved_IP, "157.55.59.128", "255.255.255.128")   ||
                 isInNet(resolved_IP, "157.55.130.0", "255.255.255.128")    ||
                 isInNet(resolved_IP, "157.56.53.128", "255.255.255.128")   ||
                 isInNet(resolved_IP, "157.56.55.0", "255.255.255.128")     ||
                 isInNet(resolved_IP, "157.56.58.0", "255.255.255.128")     ||
                 isInNet(resolved_IP, "157.56.151.0", "255.255.255.128")    ||
                 isInNet(resolved_IP, "191.232.2.128", "255.255.255.128")   ||
                 isInNet(resolved_IP, "191.237.248.32", "255.255.255.248")  ||
                 isInNet(resolved_IP, "191.237.252.192", "255.255.255.240") ||
                 isInNet(resolved_IP, "13.107.6.150", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.6.168", "255.255.255.255")    ||
                 isInNet(resolved_IP, "13.107.9.150", "255.255.255.254")    ||
                 isInNet(resolved_IP, "13.107.9.168", "255.255.255.255")    ||
                 isInNet(resolved_IP, "40.108.0.0", "255.255.224.0")        ||
                 isInNet(resolved_IP, "40.108.128.0", "255.255.128.0")      ||
                 isInNet(resolved_IP, "52.104.0.0", "255.252.0.0")          ||
                 isInNet(resolved_IP, "104.146.0.0", "255.255.224.0")       ||
                 isInNet(resolved_IP, "104.146.128.0", "255.255.128.0")     ||
                 isInNet(resolved_IP, "134.170.200.0", "255.255.248.0")     ||
                 isInNet(resolved_IP, "134.170.208.0", "255.255.248.0")     ||
                 isInNet(resolved_IP, "191.232.0.0", "255.255.254.0")       ||
                 isInNet(resolved_IP, "191.235.0.0", "255.255.240.0")       ||
                 isInNet(resolved_IP, "23.103.132.0", "255.255.252.0")      ||
                 isInNet(resolved_IP, "23.103.136.0", "255.255.248.0")      ||
                 isInNet(resolved_IP, "23.103.144.0", "255.255.240.0")      ||
                 isInNet(resolved_IP, "23.103.198.0", "255.255.254.0")      ||
                 isInNet(resolved_IP, "23.103.200.0", "255.255.252.0")      ||
                 isInNet(resolved_IP, "23.103.212.0", "255.255.252.0")      ||
                 isInNet(resolved_IP, "40.92.0.0", "255.252.0.0")           ||
                 isInNet(resolved_IP, "40.107.0.0", "255.255.128.0")        ||
                 isInNet(resolved_IP, "40.107.128.0", "255.255.192.0")      ||
                 isInNet(resolved_IP, "52.100.0.0", "255.252.0.0")          ||
                 isInNet(resolved_IP, "65.55.88.0", "255.255.255.0")        ||
                 isInNet(resolved_IP, "65.55.169.0", "255.255.255.0")       ||
                 isInNet(resolved_IP, "94.245.120.64", "255.255.255.192")   ||
                 isInNet(resolved_IP, "104.47.0.0", "255.255.128.0")        ||
                 isInNet(resolved_IP, "134.170.132.0", "255.255.255.0")     ||
                 isInNet(resolved_IP, "134.170.140.0", "255.255.255.0")     ||
                 isInNet(resolved_IP, "157.55.234.0", "255.255.255.0")      ||
                 isInNet(resolved_IP, "157.56.110.0", "255.255.254.0")      ||
                 isInNet(resolved_IP, "157.56.112.0", "255.255.255.0")      ||
                 isInNet(resolved_IP, "207.46.51.64", "255.255.255.192")    ||
                 isInNet(resolved_IP, "207.46.100.0", "255.255.255.0")      ||
                 isInNet(resolved_IP, "207.46.163.0", "255.255.255.0")      ||
                 isInNet(resolved_IP, "213.199.154.0", "255.255.255.0")     ||
                 isInNet(resolved_IP, "213.199.180.128", "255.255.255.192") ||
                 isInNet(resolved_IP, "216.32.180.0", "255.255.254.0")      ||
                 isInNet(resolved_IP, "40.100.155.8", "255.255.255.255")    ||
                 isInNet(resolved_IP, "40.100.156.24", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.100.156.136", "255.255.255.255")  ||
                 isInNet(resolved_IP, "132.245.241.56", "255.255.255.255")  ||
                 isInNet(resolved_IP, "40.100.52.8", "255.255.255.255")     ||
                 isInNet(resolved_IP, "40.100.52.136", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.100.53.8", "255.255.255.255")     ||
                 isInNet(resolved_IP, "40.100.154.56", "255.255.255.255")   ||
                 isInNet(resolved_IP, "40.100.154.168", "255.255.255.255")  ||
                 shExpMatch(host, "smtp.office365.com")                     ||
                 shExpMatch(host, "outlook.office365.com")                  ||
                 shExpMatch(host, "*.outlook.office.com")                   ||
                 shExpMatch(host, "autodiscover-*.outlook.com")             ||
                 shExpMatch(host, "*.outlook.com")                          ||
                 shExpMatch(host, "domains.live.com")                       ||
                 shExpMatch(host, "*.protection.outlook.com")               ||
                 shExpMatch(host, "*.sharepoint.com")                       ||
                 shExpMatch(host, "*.svc.ms")                               ||
                 shExpMatch(host, "login.microsoftonline.com")              ||
                 shExpMatch(host, "provisioningapi.microsoftonline.com")    ||
                 shExpMatch(host, "autodiscover.konicaminolta.com")){
                return "PROXY 10.243.255.1:8080";
        }


      if (shExpMatch(host, "*.bmwx.local")                          ||
          shExpMatch(host, "*.kmr1.local")                ||
          shExpMatch(host, "pals2web1.konicaminolta.org")                ||
          shExpMatch(host, "bmwx.konicaminolta.org")                ||
          shExpMatch(host, "*.bmwx.konicaminolta.org")              ||
          shExpMatch(host, "server2.kmcn.local")                    ||
          shExpMatch(host, "*.sap.konicaminolta.org")               ||
          shExpMatch(host, "dwh51.konicaminolta.org")               ||
          shExpMatch(host, "dwh50.konicaminolta.org")               ||
          shExpMatch(host, "meta01.konicaminolta.org")              ||
          shExpMatch(host, "eip3.konicaminolta.org")                ||
          shExpMatch(host, "eip31.konicaminolta.org")               ||
          shExpMatch(host, "eip32.konicaminolta.org")               ||
          shExpMatch(host, "geip3.konicaminolta.org")               ||
          shExpMatch(host, "kmdoc3.konicaminolta.org")              ||
          shExpMatch(host, "*.corp.konicaminolta.com.hk")           ||
          shExpMatch(host, "*.bmhk.konicaminolta.com.hk")           ||
          shExpMatch(host, "*.bmdg.konicaminolta.com.hk")           ||
          shExpMatch(host, "exmail.konicaminolta.com")              ||
          shExpMatch(host, "failback.konicaminolta.com")            ||
          shExpMatch(host, "ews.konicaminolta.com")                 ||
          shExpMatch(host, "oab.konicaminolta.com")                 ||
          shExpMatch(host, "oa.konicaminolta.com")                  ||
          shExpMatch(host, "eas.konicaminolta.com")                 ||
          shExpMatch(host, "autodiscover.konicaminolta.com")        ||
          shExpMatch(host, "rpccaca.attkm.local")                   ||
          shExpMatch(host, "pop.konicaminolta.com")                 ||
          shExpMatch(host, "imap.konicaminolta.com")                ||
          shExpMatch(host, "rms.konicaminolta.org")                 ||
          shExpMatch(host, "bthyp01prd.konicaminolta.org")          ||
          shExpMatch(host, "btsp1.konicaminolta.org")               ||
          shExpMatch(host, "gidms01.konicaminolta.org")             ||
          shExpMatch(host, "gidms03.konicaminolta.org")             ||
          shExpMatch(host, "gsso.konicaminolta.com")                ||
          shExpMatch(host, "gssosp.konicaminolta.com")              ||
          shExpMatch(host, "globalpwcr.konicaminolta.org")          ||
          shExpMatch(host, "gssoportal01.konicaminolta.com")        ||
          shExpMatch(host, "apacorder.konicaminolta.com")           ||
          shExpMatch(host, "apacorder2.konicaminolta.com")          ||
          shExpMatch(host, "apacordercn.konicaminolta.com")         ||
          shExpMatch(host, "apacorder2cn.konicaminolta.com")        ||
          shExpMatch(host, "lync2013fe01.kmjp.local")               ||
          shExpMatch(host, "lync2013fe02.kmjp.local")               ||
          shExpMatch(host, "lync2013fe03.kmjp.local")               ||
          shExpMatch(host, "lync2013fe04.kmjp.local")               ||
          shExpMatch(host, "ly13-fepool.kmjp.local")                ||
          shExpMatch(host, "ly13-edpool.kmjp.local")                ||
          shExpMatch(host, "lync2013wac01.kmjp.local")              ||
          shExpMatch(host, "wacfarm.konicaminolta.com")             ||
          shExpMatch(host, "ly13-chatpool.kmjp.local")              ||
          shExpMatch(host, "tableau-bi.konicaminolta.com")              ||
          shExpMatch(host, "kmsf1.konicaminolta.com")               ||
          shExpMatch(host, "*.boxcn.net")               ||
          shExpMatch(host, "konicaminolta.app.box.com")               ||
          dnsDomainIs(host, "tel.konicaminolta.org")                ||
          shExpMatch(host, "150.16.221.203")                        ||
          shExpMatch(host, "192.168.1.*")                           ||
          shExpMatch(host, "192.168.2.*")                           ||
          shExpMatch(host, "192.168.4.*")                           ||
          shExpMatch(host, "192.168.5.*")                           ||
          shExpMatch(host, "192.168.6.*")                           ||
          shExpMatch(host, "192.168.201.*")                         ||
          shExpMatch(host, "150.16.61.*")                           ||
          shExpMatch(host, "150.16.62.*")                           ||
          shExpMatch(host, "150.16.139.*")                          ||
          shExpMatch(host, "150.16.249.*")                          ||
          shExpMatch(host, "150.17.84.41")                          ||
          shExpMatch(host, "10.240.*")                              ||
          shExpMatch(host, "10.241.16.*")                           ||
          shExpMatch(host, "10.241.48.*")                           ||
          shExpMatch(host, "10.241.49.*")                           ||
          shExpMatch(host, "10.241.50.*")                           ||
          shExpMatch(host, "10.241.51.*")                           ||
          shExpMatch(host, "10.241.52.*")                           ||
          shExpMatch(host, "10.241.53.*")                           ||
          shExpMatch(host, "10.241.54.*")                           ||
          shExpMatch(host, "10.241.55.*")                           ||
          shExpMatch(host, "10.241.56.*")                           ||
          shExpMatch(host, "10.241.57.*")                           ||
          shExpMatch(host, "10.241.58.*")                           ||
          shExpMatch(host, "10.241.59.*")                           ||
          shExpMatch(host, "10.241.60.*")                           ||
          shExpMatch(host, "10.241.61.*")                           ||
          shExpMatch(host, "10.241.62.*")                           ||
          shExpMatch(host, "10.241.63.*")                           ||
          shExpMatch(host, "10.241.64.*")                           ||
          shExpMatch(host, "127.0.0.1")                             ||
          shExpMatch(host, "localhost")                             ||
	  shExpMatch(host, "*.bmhk.local")                             ||
	  shExpMatch(host, "10.241.134.*")                            ||
          shExpMatch(host, "10.241.135.*")                            ||
          shExpMatch(host, "10.241.136.*")                            ||
          shExpMatch(host, "150.16.236.*")                            ||
          shExpMatch(host, "10.241.5.*")                            ||
          shExpMatch(host, "10.241.13.*")                           ||
          shExpMatch(host, "10.241.70.*")                           ||
          shExpMatch(host, "10.241.71.*")                           ||
          shExpMatch(host, "150.17.206.*")                          ||
          shExpMatch(host, "150.17.207.*")                          ||
          shExpMatch(host, "150.17.232.*")                          ||
          shExpMatch(host, "150.17.233.*")                          ||
          shExpMatch(host, "150.17.234.*")                          ||
          shExpMatch(host, "150.17.235.*")                          ||
          shExpMatch(host, "150.17.236.*")                          ||
          shExpMatch(host, "150.17.237.*")                          ||
          shExpMatch(host, "150.17.238.*")                          ||
          shExpMatch(host, "10.203.56.58")                          ||
          shExpMatch(host, "150.17.187.180")                        ||
          shExpMatch(host, "10.241.129.*")                        ||
          shExpMatch(host, "10.254.112.167")                        ||
          shExpMatch(host, "10.203.56.79")                        ||
          shExpMatch(host, "10.254.112.161")                        ||
          shExpMatch(host, "10.254.112.162")                        ||
          shExpMatch(host, "10.254.112.163")                        ||
          shExpMatch(host, "10.254.112.164")                        ||
          shExpMatch(host, "10.254.112.165")                        ||
          shExpMatch(host, "150.17.187.70")                        ||
	  shExpMatch(host, "150.17.187.71")                        ||
          shExpMatch(host, "150.17.187.72")                        ||
          shExpMatch(host, "150.17.187.73")                        ||
          shExpMatch(host, "150.17.187.74")                        ||
          shExpMatch(host, "10.203.25.64")                        ||
          isInNet(host, "63.241.62.64", "255.255.255.240")          ||
          isInNet(host, "63.241.62.128", "255.255.255.192")         ||
          isInNet(host, "63.241.62.192", "255.255.255.224")         ||
          shExpMatch(host, "150.17.239.*")) {
          	return "DIRECT";
          }

/* Domains are in Japan side. Proxy Hachioji     */
      if (dnsDomainIs(host, "exmail.konicaminolta.org")             ||
          dnsDomainIs(host, "es.pro.konicaminolta.jp")              ||
          dnsDomainIs(host, "spad.konicaminolta.jp")                ||
          dnsDomainIs(host, "hakobe.konicaminolta.org")             ||
          dnsDomainIs(host, "xdrv.konicaminolta.jp")                ||
          dnsDomainIs(host, "bttooling.konicaminolta.org")          ||
          dnsDomainIs(host, "greenapdb.konicaminolta.org")          ||
          dnsDomainIs(host, "fc-1.bt.konicaminolta.jp")             ||
          dnsDomainIs(host, "rohsdb.konicaminolta.org")             ||
          dnsDomainIs(host, "coconet.konicaminolta.net")            ||
          dnsDomainIs(host, "e-shindan.konicaminolta.jp")           ||
          dnsDomainIs(host, "vconference.konicaminolta.jp")         ||
          dnsDomainIs(host, "vconference2.konicaminolta.jp")        ||
          dnsDomainIs(host, "vconference3.konicaminolta.jp")        ||
          dnsDomainIs(host, "vconference4.konicaminolta.jp")        ||
          dnsDomainIs(host, "square.konicaminolta.jp")              ||
          dnsDomainIs(host, "tokoro.konicaminolta.org")             ||
          dnsDomainIs(host, "laura.tokyo.konicaminolta.jp")         ||
          dnsDomainIs(host, "bd-report.com")                        ||
	  dnsDomainIs(host, "vmroperator.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf1.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf2.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf3.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf4.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf5.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf6.konicaminolta.jp")                        ||
          dnsDomainIs(host, "pexipcnf7.konicaminolta.jp")                        ||
          dnsDomainIs(host, ".bd-report.com")                       ||
          dnsDomainIs(host, "btdhs1.konicaminolta.org")             ||
          dnsDomainIs(host, "ebom-ap.konicaminolta.org")            ||
          shExpMatch(host, "ctldl.windowsupdate.com")               ||
          shExpMatch(host, "SVRIntl-G3-crl.verisign.com")           ||
          shExpMatch(host, "crl.verisign.com")                      ||
          shExpMatch(host, "cdp1.public-trust.com")                 ||
          shExpMatch(host, "gcpfimapp01.kmg1.konicaminolta.com")                 ||
          shExpMatch(host, "crl.omniroot.com")                      ||
          shExpMatch(host, "se.symcb.com")                          ||
          shExpMatch(host, "btdhs1.konicaminolta.org")              ||
          shExpMatch(host, "bsljt.konicaminolta.jp")              ||
          shExpMatch(host, "150.16.92.193")                         ||
          shExpMatch(host, "150.17.45.8")                           ||
          shExpMatch(host, "10.16.112.34")                          ||
          shExpMatch(host, "new-green-p.konicaminolta.org")) {
	          return "PROXY 150.17.45.29:8080";
          }

/* Domains are in Japan side. Proxy Seishin     */
      if (dnsDomainIs(host, "wallaby.tdc.konicaminolta.jp")         || 
          dnsDomainIs(host, "eisrd.tdc.konicaminolta.jp")           ||
          dnsDomainIs(host, "csesweb.bt.konicaminolta.jp")          ||
          dnsDomainIs(host, "csesftp.bt.konicaminolta.jp")          ||
          dnsDomainIs(host, "csesoep.bt.konicaminolta.jp")          ||
          dnsDomainIs(host, ".konicaminolta.org")                   ||
          dnsDomainIs(host, "www.konicaminolta.jp")                 ||
          dnsDomainIs(host, "150.17.87.1")                          ||
          dnsDomainIs(host, "10.254.112.22")                        ||
          dnsDomainIs(host, "10.254.112.23")                        ||
          dnsDomainIs(host, "scm17rr01.kmjp.local")                        ||
          dnsDomainIs(host, "10.254.112.100")) {
       		   return "PROXY 150.17.45.3:3128";
          }

/* Domains are in Japan side. Proxy Seishin*/
      if (dnsDomainIs(host, "150.17.240.40")                        ||
          dnsDomainIs(host, ".konica.co.jp")                        ||
          dnsDomainIs(host, ".minolta.co.jp")                       ||
          dnsDomainIs(host, "kmbi-rs.test.konicaminolta.org")       ||
          dnsDomainIs(host, "kompas-rs.test.konicaminolta.org")     ||
          dnsDomainIs(host, "kmbi-rs.konicaminolta.org")            ||
          dnsDomainIs(host, "kompas-rs.konicaminolta.org")          ||
          dnsDomainIs(host, ".konicaminolta.jp")) {
	          return "PROXY 150.17.45.29:3128";
          }

/* BMDG */
      if (host_ip.substr(0, 10) == "10.241.13."                       ||
          host_ip.substr(0, 9) == "10.241.70"                       ||
          host_ip.substr(0, 9) == "10.241.71"                       ||
          host_ip.substr(0, 10) == "150.17.206"                     ||
          host_ip.substr(0, 10) == "150.17.207"                     ||
          host_ip.substr(0, 10) == "150.17.232"                     ||
          host_ip.substr(0, 10) == "150.17.233"                     ||
          host_ip.substr(0, 10) == "150.17.234"                     ||
          host_ip.substr(0, 10) == "150.17.235"                     ||
          host_ip.substr(0, 10) == "150.17.236"                     ||
          host_ip.substr(0, 10) == "150.17.237"                     ||
          host_ip.substr(0, 10) == "150.17.238"                     ||
          host_ip.substr(0, 10) == "150.17.239") {
          if (
              shExpMatch(host, "login.live.com")                    ||
              shExpMatch(host, "office.live.com")                   ||
              shExpMatch(host, "officeapps.live.com")               ||
              shExpMatch(host, "online.lync.com")                   ||
              shExpMatch(host, "lync.com")                          ||
              shExpMatch(host, "skydrive.live.com")                 ||
              shExpMatch(host, "onedrive.live.com")                 ||
              shExpMatch(host, "outlook.com")                       ||
              shExpMatch(host, "office365.com")                     ||
              shExpMatch(host, "r1.res.office365.com")              ||
              shExpMatch(host, "r3.res.outlook.com")                ||
              shExpMatch(host, "r4.res.outlook.com")                ||
              shExpMatch(host, "prod.msocdn.com")                   ||
              shExpMatch(host, "odc.officeapps.live.com")           ||
              shExpMatch(host, "d.docs.live.net")                   ||
              shExpMatch(host, "microsoftonline-p.com")             ||
              shExpMatch(host, "microsoftonline-p.net")             ||
              shExpMatch(host, "live.com")                          ||
              shExpMatch(host, "licdn.com")                         ||
              shExpMatch(host, "microsoftonline.com")               ||
              shExpMatch(host, "officecdn.microsoft.com")           ||
              shExpMatch(host, "res.office365.com")                 ||
              shExpMatch(host, "res.outlook.com")                   ||
              shExpMatch(host, "msecdn.net")                        ||
              shExpMatch(host, "ols.officeapps.live.com")           ||
              shExpMatch(host, "go.microsoft.com")                  ||
              shExpMatch(host, "activation.sls.microsoft.com")      ||
              shExpMatch(host, "crl.microsoft.com")                 ||
              shExpMatch(host, "validation.sls.microsoft.com")      ||
              shExpMatch(host, "activation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "validation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "displaycatalog.mp.microsoft.com")   ||
              shExpMatch(host, "licensing.mp.microsoft.com")        ||
              shExpMatch(host, "purchase.mp.microsoft.com")         ||
              shExpMatch(host, "displaycatalog.md.mp.microsoft.com") ||
              shExpMatch(host, "licensing.md.mp.microsoft.com")     ||
              shExpMatch(host, "purchase.md.mp.microsoft.com")      ||
              isInNet(host, "132.245.0.0", "255.255.0.0")           ||
              isInNet(host, "157.55.0.0", "255.255.0.0")            ||
              shExpMatch(host, "www.baidu.com")                ||
              shExpMatch(host, "www.hotmail.com")                ||
              shExpMatch(host, "www.microsoft.com")                ||
              shExpMatch(host, "www.outlook.com")                ||
              shExpMatch(host, "konicaminoltaglobal.sharepoint.com")                ||
              shExpMatch(host, "propluspit-9327.cloudforce.com")                ||
              shExpMatch(host, "www.timax.com.hk")                ||
              shExpMatch(host, "app02.szaic.gov.cn")                ||
              shExpMatch(host, "www.eiccoalition.org")                ||
              shExpMatch(host, "www.hitachi-metals.co.jp")                ||
              shExpMatch(host, "my.tnt.com")                ||
              shExpMatch(host, "www.alc.co.jp")                ||
              shExpMatch(host, "www.bk.mufg.jp")               ||
              shExpMatch(host, "eweb.bk.mufg.jp")                ||
              shExpMatch(host, "xerox.e2open.com")                ||
              shExpMatch(host, "e-commerce.bmwx.konicaminolta.cn")  ||
              shExpMatch(host, "zzskp.szgs.gov.cn")  ||
              shExpMatch(host, "login.windows.net")  ||
              shExpMatch(host, "*.analysis.windows.net")  ||
              shExpMatch(host, "*.servicebus.windows.net")  ||
              shExpMatch(host, "*.frontend.clouddatahub.net")  ||
              shExpMatch(host, "*.core.windows.net")  ||
              shExpMatch(host, "*.powerbi.com"))  {
              	return "PROXY 150.17.206.158:8080";
		}
              else {
              	return "PROXY 222.126.180.164:8080; PROXY 103.246.38.164:8080; PROXY 211.147.76.84:8080; DIRECT";
	      }
          }
 
/* BPO */
      if (host_ip.substr(0, 10) == "10.241.130"                       ||  // IP address range of ACN_BPO
          host_ip.substr(0, 10) == "10.241.131" ) {
          if (
              shExpMatch(host, "login.live.com")                    ||
              shExpMatch(host, "office.live.com")                   ||
              shExpMatch(host, "officeapps.live.com")               ||
              shExpMatch(host, "online.lync.com")                   ||
              shExpMatch(host, "lync.com")                          ||
              shExpMatch(host, "skydrive.live.com")                 ||
              shExpMatch(host, "onedrive.live.com")                 ||
              shExpMatch(host, "outlook.com")                       ||
              shExpMatch(host, "office365.com")                     ||
              shExpMatch(host, "r1.res.office365.com")              ||
              shExpMatch(host, "r3.res.outlook.com")                ||
              shExpMatch(host, "r4.res.outlook.com")                ||
              shExpMatch(host, "prod.msocdn.com")                   ||
              shExpMatch(host, "odc.officeapps.live.com")           ||
              shExpMatch(host, "d.docs.live.net")                   ||
              shExpMatch(host, "microsoftonline-p.com")             ||
              shExpMatch(host, "microsoftonline-p.net")             ||
              shExpMatch(host, "live.com")                          ||
              shExpMatch(host, "licdn.com")                         ||
              shExpMatch(host, "microsoftonline.com")               ||
              shExpMatch(host, "officecdn.microsoft.com")           ||
              shExpMatch(host, "res.office365.com")                 ||
              shExpMatch(host, "res.outlook.com")                   ||
              shExpMatch(host, "msecdn.net")                        ||
              shExpMatch(host, "ols.officeapps.live.com")           ||
              shExpMatch(host, "go.microsoft.com")                  ||
              shExpMatch(host, "activation.sls.microsoft.com")      ||
              shExpMatch(host, "crl.microsoft.com")                 ||
              shExpMatch(host, "validation.sls.microsoft.com")      ||
              shExpMatch(host, "activation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "validation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "displaycatalog.mp.microsoft.com")   ||
              shExpMatch(host, "licensing.mp.microsoft.com")        ||
              shExpMatch(host, "purchase.mp.microsoft.com")         ||
              shExpMatch(host, "displaycatalog.md.mp.microsoft.com") ||
              shExpMatch(host, "licensing.md.mp.microsoft.com")     ||
              shExpMatch(host, "purchase.md.mp.microsoft.com")      ||
              isInNet(host, "132.245.0.0", "255.255.0.0")           ||
              isInNet(host, "157.55.0.0", "255.255.0.0")            ||
              shExpMatch(host, "www.baidu.com")                ||
              shExpMatch(host, "www.hotmail.com")                ||
              shExpMatch(host, "www.microsoft.com")                ||
              shExpMatch(host, "www.outlook.com")                ||
              shExpMatch(host, "konicaminoltaglobal.sharepoint.com")                ||
              shExpMatch(host, "propluspit-9327.cloudforce.com")                ||
              shExpMatch(host, "www.timax.com.hk")                ||
              shExpMatch(host, "app02.szaic.gov.cn")                ||
              shExpMatch(host, "www.eiccoalition.org")                ||
              shExpMatch(host, "www.hitachi-metals.co.jp")                ||
              shExpMatch(host, "my.tnt.com")                ||
              shExpMatch(host, "www.alc.co.jp")                ||
              shExpMatch(host, "www.bk.mufg.jp")               ||
              shExpMatch(host, "eweb.bk.mufg.jp")                ||
              shExpMatch(host, "xerox.e2open.com")                ||
              shExpMatch(host, "e-commerce.bmwx.konicaminolta.cn")  ||
              shExpMatch(host, "procuremeister.t2.eiplaza.com")  ||
              shExpMatch(host, "zzskp.szgs.gov.cn")  ||
              shExpMatch(host, "login.windows.net")  ||
              shExpMatch(host, "*.analysis.windows.net")  ||
              shExpMatch(host, "*.accenture.com")  ||
              shExpMatch(host, "*.servicebus.windows.net")  ||
              shExpMatch(host, "*.frontend.clouddatahub.net")  ||
              shExpMatch(host, "*.core.windows.net")  ||
              shExpMatch(host, "*.powerbi.com"))  {
   return "PROXY 10.241.16.27:8080";  // this is the IP of BCSZ(SH) proxy
   }
              else {
                return "PROXY 211.147.76.84:8080; PROXY 103.246.38.164:8080; DIRECT";  // IP addresses of cwss
   }
        }

/* BMHK */
      if (host_ip.substr(0, 10) == "150.17.215"                       ||
	  host_ip.substr(0, 10) == "10.241.134"                       ||
          host_ip.substr(0, 10) == "10.241.135"                       ||
          host_ip.substr(0, 10) == "10.241.136"                       ||
          host_ip.substr(0, 10) == "10.241.129"                       ||
          host_ip.substr(0, 7) == "169.254"                       ||
          host_ip.substr(0, 9) == "10.241.64") {
          if (
              shExpMatch(host, "login.live.com")                    ||
              shExpMatch(host, "office.live.com")                   ||
              shExpMatch(host, "officeapps.live.com")               ||
              shExpMatch(host, "online.lync.com")                   ||
              shExpMatch(host, "lync.com")                          ||
              shExpMatch(host, "skydrive.live.com")                 ||
              shExpMatch(host, "onedrive.live.com")                 ||
              shExpMatch(host, "outlook.com")                       ||
              shExpMatch(host, "office365.com")                     ||
              shExpMatch(host, "r1.res.office365.com")              ||
              shExpMatch(host, "r3.res.outlook.com")                ||
              shExpMatch(host, "r4.res.outlook.com")                ||
              shExpMatch(host, "prod.msocdn.com")                   ||
              shExpMatch(host, "odc.officeapps.live.com")           ||
              shExpMatch(host, "d.docs.live.net")                   ||
              shExpMatch(host, "microsoftonline-p.com")             ||
              shExpMatch(host, "microsoftonline-p.net")             ||
              shExpMatch(host, "live.com")                          ||
              shExpMatch(host, "licdn.com")                         ||
              shExpMatch(host, "microsoftonline.com")               ||
              shExpMatch(host, "officecdn.microsoft.com")           ||
              shExpMatch(host, "res.office365.com")                 ||
              shExpMatch(host, "res.outlook.com")                   ||
              shExpMatch(host, "msecdn.net")                        ||
              shExpMatch(host, "ols.officeapps.live.com")           ||
              shExpMatch(host, "go.microsoft.com")                  ||
              shExpMatch(host, "activation.sls.microsoft.com")      ||
              shExpMatch(host, "crl.microsoft.com")                 ||
              shExpMatch(host, "validation.sls.microsoft.com")      ||
              shExpMatch(host, "activation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "validation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "displaycatalog.mp.microsoft.com")   ||
              shExpMatch(host, "licensing.mp.microsoft.com")        ||
              shExpMatch(host, "purchase.mp.microsoft.com")         ||
              shExpMatch(host, "displaycatalog.md.mp.microsoft.com") ||
              shExpMatch(host, "licensing.md.mp.microsoft.com")     ||
              shExpMatch(host, "purchase.md.mp.microsoft.com")      ||
              isInNet(host, "132.245.0.0", "255.255.0.0")           ||
              isInNet(host, "157.55.0.0", "255.255.0.0")            ||
              shExpMatch(host, "www.baidu.com")                ||
              shExpMatch(host, "www.hotmail.com")                ||
              shExpMatch(host, "www.microsoft.com")                ||
              shExpMatch(host, "www.outlook.com")                ||
              shExpMatch(host, "konicaminoltaglobal.sharepoint.com")                ||
              shExpMatch(host, "propluspit-9327.cloudforce.com")                ||
              shExpMatch(host, "www.timax.com.hk")                ||
              shExpMatch(host, "app02.szaic.gov.cn")                ||
              shExpMatch(host, "www.eiccoalition.org")                ||
              shExpMatch(host, "www.hitachi-metals.co.jp")                ||
              shExpMatch(host, "my.tnt.com")                ||
              shExpMatch(host, "www.alc.co.jp")                ||
              shExpMatch(host, "www.bk.mufg.jp")               ||
              shExpMatch(host, "eweb.bk.mufg.jp")                ||
              shExpMatch(host, "xerox.e2open.com")                ||
              shExpMatch(host, "e-commerce.bmwx.konicaminolta.cn")  ||
              shExpMatch(host, "zzskp.szgs.gov.cn")  ||
              shExpMatch(host, "login.windows.net")  ||
              shExpMatch(host, "*.analysis.windows.net")  ||
              shExpMatch(host, "*.servicebus.windows.net")  ||
              shExpMatch(host, "*.frontend.clouddatahub.net")  ||
              shExpMatch(host, "*.core.windows.net")  ||
              shExpMatch(host, "*.powerbi.com"))  {
		return "PROXY 10.241.129.141:8080";
	     }
              else {
              	return "PROXY 103.246.38.164:8080; PROXY 103.246.37.164:8080; DIRECT";
	      }
          }

/* BCSZ Shanghai */
      if (host_ip.substr(0, 9) == "10.241.16"                       ||
          host_ip.substr(0, 9) == "10.241.17" ) {
          if (
              shExpMatch(host, "login.live.com")                    ||
              shExpMatch(host, "office.live.com")                   ||
              shExpMatch(host, "officeapps.live.com")               ||
              shExpMatch(host, "online.lync.com")                   ||
              shExpMatch(host, "lync.com")                          ||
              shExpMatch(host, "skydrive.live.com")                 ||
              shExpMatch(host, "onedrive.live.com")                 ||
              shExpMatch(host, "outlook.com")                       ||
              shExpMatch(host, "office365.com")                     ||
              shExpMatch(host, "r1.res.office365.com")              ||
              shExpMatch(host, "r3.res.outlook.com")                ||
              shExpMatch(host, "r4.res.outlook.com")                ||
              shExpMatch(host, "prod.msocdn.com")                   ||
              shExpMatch(host, "odc.officeapps.live.com")           ||
              shExpMatch(host, "d.docs.live.net")                   ||
              shExpMatch(host, "microsoftonline-p.com")             ||
              shExpMatch(host, "microsoftonline-p.net")             ||
              shExpMatch(host, "live.com")                          ||
              shExpMatch(host, "licdn.com")                         ||
              shExpMatch(host, "microsoftonline.com")               ||
              shExpMatch(host, "officecdn.microsoft.com")           ||
              shExpMatch(host, "res.office365.com")                 ||
              shExpMatch(host, "res.outlook.com")                   ||
              shExpMatch(host, "msecdn.net")                        ||
              shExpMatch(host, "ols.officeapps.live.com")           ||
              shExpMatch(host, "go.microsoft.com")                  ||
              shExpMatch(host, "activation.sls.microsoft.com")      ||
              shExpMatch(host, "crl.microsoft.com")                 ||
              shExpMatch(host, "validation.sls.microsoft.com")      ||
              shExpMatch(host, "activation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "validation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "displaycatalog.mp.microsoft.com")   ||
              shExpMatch(host, "licensing.mp.microsoft.com")        ||
              shExpMatch(host, "purchase.mp.microsoft.com")         ||
              shExpMatch(host, "displaycatalog.md.mp.microsoft.com") ||
              shExpMatch(host, "licensing.md.mp.microsoft.com")     ||
              shExpMatch(host, "purchase.md.mp.microsoft.com")      ||
              shExpMatch(host, "procuremeister.t2.eiplaza.com")      ||
              isInNet(host, "132.245.0.0", "255.255.0.0")           ||
              isInNet(host, "157.55.0.0", "255.255.0.0")            ||
              shExpMatch(host, "www.baidu.com")                ||
              shExpMatch(host, "www.hotmail.com")                ||
              shExpMatch(host, "www.microsoft.com")                ||
              shExpMatch(host, "www.outlook.com")                ||
              shExpMatch(host, "konicaminoltaglobal.sharepoint.com")                ||
              shExpMatch(host, "propluspit-9327.cloudforce.com")                ||
              shExpMatch(host, "www.timax.com.hk")                ||
              shExpMatch(host, "app02.szaic.gov.cn")                ||
              shExpMatch(host, "www.eiccoalition.org")                ||
              shExpMatch(host, "www.hitachi-metals.co.jp")                ||
              shExpMatch(host, "my.tnt.com")                ||
              shExpMatch(host, "www.alc.co.jp")                ||
              shExpMatch(host, "www.bk.mufg.jp")               ||
              shExpMatch(host, "eweb.bk.mufg.jp")                ||
              shExpMatch(host, "xerox.e2open.com")                ||
              shExpMatch(host, "e-commerce.bmwx.konicaminolta.cn")  ||
              shExpMatch(host, "zzskp.szgs.gov.cn")  ||
              shExpMatch(host, "login.windows.net")  ||
              shExpMatch(host, "*.analysis.windows.net")  ||
              shExpMatch(host, "*.servicebus.windows.net")  ||
              shExpMatch(host, "*.frontend.clouddatahub.net")  ||
              shExpMatch(host, "*.core.windows.net")  ||
              shExpMatch(host, "*.powerbi.com")  ||
              shExpMatch(host, "zzskp.szgs.gov.cn")  ||
              shExpMatch(host, "login.windows.net")  ||
              shExpMatch(host, "*.analysis.windows.net")  ||
              shExpMatch(host, "*.servicebus.windows.net")  ||
              shExpMatch(host, "*.frontend.clouddatahub.net")  ||
              shExpMatch(host, "*.core.windows.net")  ||
              shExpMatch(host, "*.powerbi.com"))  {
			return "PROXY 10.241.16.27:8080";
		}
              else {
              		return "PROXY 211.147.76.84:8080; PROXY 103.246.38.164:8080; DIRECT";
		}
          }

/* BCSZ Shenzhen */
      if (host_ip.substr(0, 9) == "150.16.61"                       ||
          host_ip.substr(0, 9) == "150.16.62" ) {
          if (
              shExpMatch(host, "login.live.com")                    ||
              shExpMatch(host, "office.live.com")                   ||
              shExpMatch(host, "officeapps.live.com")               ||
              shExpMatch(host, "online.lync.com")                   ||
              shExpMatch(host, "lync.com")                          ||
              shExpMatch(host, "skydrive.live.com")                 ||
              shExpMatch(host, "onedrive.live.com")                 ||
              shExpMatch(host, "outlook.com")                       ||
              shExpMatch(host, "office365.com")                     ||
              shExpMatch(host, "r1.res.office365.com")              ||
              shExpMatch(host, "r3.res.outlook.com")                ||
              shExpMatch(host, "r4.res.outlook.com")                ||
              shExpMatch(host, "prod.msocdn.com")                   ||
              shExpMatch(host, "odc.officeapps.live.com")           ||
              shExpMatch(host, "d.docs.live.net")                   ||
              shExpMatch(host, "microsoftonline-p.com")             ||
              shExpMatch(host, "microsoftonline-p.net")             ||
              shExpMatch(host, "live.com")                          ||
              shExpMatch(host, "licdn.com")                         ||
              shExpMatch(host, "microsoftonline.com")               ||
              shExpMatch(host, "officecdn.microsoft.com")           ||
              shExpMatch(host, "res.office365.com")                 ||
              shExpMatch(host, "res.outlook.com")                   ||
              shExpMatch(host, "msecdn.net")                        ||
              shExpMatch(host, "ols.officeapps.live.com")           ||
              shExpMatch(host, "go.microsoft.com")                  ||
              shExpMatch(host, "activation.sls.microsoft.com")      ||
              shExpMatch(host, "crl.microsoft.com")                 ||
              shExpMatch(host, "validation.sls.microsoft.com")      ||
              shExpMatch(host, "activation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "validation-v2.sls.microsoft.com")   ||
              shExpMatch(host, "displaycatalog.mp.microsoft.com")   ||
              shExpMatch(host, "licensing.mp.microsoft.com")        ||
              shExpMatch(host, "purchase.mp.microsoft.com")         ||
              shExpMatch(host, "displaycatalog.md.mp.microsoft.com") ||
              shExpMatch(host, "licensing.md.mp.microsoft.com")     ||
              shExpMatch(host, "purchase.md.mp.microsoft.com")      ||
              isInNet(host, "132.245.0.0", "255.255.0.0")           ||
              isInNet(host, "157.55.0.0", "255.255.0.0")            ||
              shExpMatch(host, "www.baidu.com")                ||
              shExpMatch(host, "www.hotmail.com")                ||
              shExpMatch(host, "www.microsoft.com")                ||
              shExpMatch(host, "www.outlook.com")                ||
              shExpMatch(host, "konicaminoltaglobal.sharepoint.com")                ||
              shExpMatch(host, "propluspit-9327.cloudforce.com")                ||
              shExpMatch(host, "www.timax.com.hk")                ||
              shExpMatch(host, "app02.szaic.gov.cn")                ||
              shExpMatch(host, "www.eiccoalition.org")                ||
              shExpMatch(host, "www.hitachi-metals.co.jp")                ||
              shExpMatch(host, "my.tnt.com")                ||
              shExpMatch(host, "www.alc.co.jp")                ||
              shExpMatch(host, "www.bk.mufg.jp")               ||
              shExpMatch(host, "eweb.bk.mufg.jp")                ||
              shExpMatch(host, "xerox.e2open.com")                ||
              shExpMatch(host, "e-commerce.bmwx.konicaminolta.cn")  ||
              shExpMatch(host, "zzskp.szgs.gov.cn")  ||
              shExpMatch(host, "login.windows.net")  ||
              shExpMatch(host, "*.analysis.windows.net")  ||
              shExpMatch(host, "*.servicebus.windows.net")  ||
              shExpMatch(host, "*.frontend.clouddatahub.net")  ||
              shExpMatch(host, "*.core.windows.net")  ||
              shExpMatch(host, "*.powerbi.com"))  {
			return "PROXY 150.16.62.181:8080";
		}
	if (shExpMatch(host, "procuremeister.t2.eiplaza.com"))
		        {return "PROXY 10.241.16.27:8080";}
              else {
      		        return "PROXY 222.126.180.164:8080; PROXY 103.246.38.164:8080; PROXY 211.147.76.84:8080; DIRECT";
		}
          }

      if (isPlainHostName(host)) {
          return "DIRECT";
          }

      if (host_ip.substr(0, 10) == "10.16.2.67") {
          return "PROXY 150.17.45.3:3128";
          }

      return "PROXY 150.17.45.29:3128";
      }
	  
	  test2 20190515