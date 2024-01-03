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
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group15-sha512",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group17-sha512",
            "diffie-hellman-group18-sha512",
            "ecdh-sha2-",
            "ecmqv-sha2-",
            "gss-",
            "rsa1024-sha1",
        ],
        "encryption_algorithms": ["des-cbc", "3des-cbc", "rc4", "des-ede"],
        "mac_algorithms": ["hmac-md5", "hmac-sha1", "umac-64"],
        "server_host_key_algorithms": [
            "ssh-rsa",
            "ssh-dss",
            "ecdsa-sha2-",
            "ssh-ed25519",
        ],
    }
