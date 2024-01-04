class Config:
    domainname_list = "small.txt"
    portrange = "22,80,113,443,444"
    enable_geoip = True
    enable_asn = True
    geoip_city_path = "GeoLite2-City.mmdb"
    geoip_asn_path = "GeoLite2-ASN.mmdb"

    ssh_server_identifiers = [  # Identifiers used to identify a SSH server
        "ssh",
        "openssh",
        "dropbear",
        "bitvise-ssh",
        "microsft-ssh",
    ]

    unsafe_ssh_algorithms = {  # This list is used by checking the start of the string
        "kex_algorithms": [
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "gss-",
            "rsa1024-sha1",
        ],
        "encryption_algorithms": [
            "3des-cbc",
            "arcfour",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "des-cbc",
            "des-ede",
            "idea-cbc",
            "rc4",
        ],
        "mac_algorithms": ["hmac-md5", "hmac-sha1", "umac-64", "hmac-ripemd160", "umac-128-etm"],
        "server_host_key_algorithms": ["ssh-dss", "ssh-rsa"],
    }
