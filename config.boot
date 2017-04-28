firewall {
    all-ping enable
    broadcast-ping disable
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians enable
    name WAN_IN {
        default-action drop
        description "incoming on WAN"
        rule 10 {
            action accept
            description "WAN valid established"
            state {
                established enable
                related enable
            }
        }

        /* Rules allowing WAN -> DMZ connections go here. */
        
        rule 20 {
            action drop
            description "WAN new & invalid"
            state {
                invalid enable
                new enable
            }
        }
    }
    name WAN_LOCAL {
        default-action drop
        description "WAN to router"
    }
    name DMZ_IN {
        default-action drop
        description "incoming to DMZ "
        rule 10 {
            action accept
            description "DMZ valid established"
            state {
                established enable
                related enable
            }
        }
        rule 20 {
            action accept
            description "DMZ new to WAN"
            destination {
                group {
                    address-group ADDRv4_eth1
                }
            }
            state {
                new enable
            }
        }
        rule 30 {
            action drop
            description "DMZ invalid"
            state {
                invalid enable
            }
        }
    }
    name DMZ_LOCAL {
        default-action drop
        description "DMZ to router"
    }
    name LAN_IN {
        default-action drop
        description "incoming on LAN"
        rule 10 {
            action accept
            description "LAN all valid"
            state {
                established enable
                new enable
                related enable
            }
        }
        rule 20 {
            action drop
            description "LAN invalid"
            state {
                invalid enable
            }
        }
    }

    /* Rules allowing LAN -> LOCAL connections go here. */

    name LAN_OUT {
        default-action drop
        description "LAN outcoming"
        rule 10 {
            action accept
            description "LAN valid existing"
            state {
                established enable
                related enable
            }
        }
        rule 20 {
            action drop
            description "LAN new & invalid"
            state {
                invalid enable
                new enable
            }
        }
    }
    options {
        mss-clamp {
            mss 1412
        }
    }
    receive-redirects disable
    send-redirects enable
    source-validation disable
    syn-cookies enable
}
interfaces {
    bridge br1 {
        address 192.168.1.1/24
        aging 300
        hello-time 2
        max-age 20
        priority 0
        promiscuous disable
        stp false
    }
    ethernet eth0 {
        description "Internet (ISP_PPPoE)"
        duplex auto
        pppoe 0 {
            default-route auto
            firewall {
                in {
                    name WAN_IN
                }
                local {
                    name WAN_LOCAL
                }
            }
            mtu 1492
            name-server auto
            password %PASSWORD%
            user-id %USERNAME%
        }
        speed auto
    }
    ethernet eth1 {
        duplex auto
        speed auto
    }
    ethernet eth2 {
        duplex auto
        speed auto
    }
    ethernet eth3 {
        duplex auto
        speed auto
    }
    ethernet eth4 {
        duplex auto
        speed auto
    }
    ethernet eth5 {
        address 192.168.2.1/24
        description WLAN
        duplex auto
        speed auto
        vif 10 {
            address 192.168.3.1/24
            description "Guest VLAN"
            mtu 1500
        }
    }
    ethernet eth6 {
        bridge-group {
            bridge br1
        }
        description LAN
        duplex auto
        speed auto
    }
    ethernet eth7 {
        bridge-group {
            bridge br1
        }
        description LAN
        duplex auto
        speed auto
    }
    loopback lo {
    }
}
service {
    dhcp-server {
        disabled false
        hostfile-update disable
        shared-network-name LAN1 {
            authoritative disable
            subnet 192.168.1.0/24 {
                default-router 192.168.1.1
                dns-server 8.8.8.8
                dns-server 8.8.4.4
                lease 86400
                start 192.168.1.2 {
                    stop 192.168.1.254
                }
                static-mapping %DEVICEHOSTNAME1% {
                    ip-address 192.168.1.100
                    mac-address e8:39:35:90:27:24
                }
                unifi-controller 192.168.1.30
            }
        }
        shared-network-name WLAN {
            authoritative disable
            subnet 192.168.2.0/24 {
                default-router 192.168.2.1
                dns-server 8.8.8.8
                dns-server 8.8.4.4
                lease 86400
                start 192.168.2.2 {
                    stop 192.168.2.254
                }
                static-mapping UAP-AC {
                    ip-address 192.168.2.2
                    mac-address 24:a4:3c:c0:1f:5b
                }
                unifi-controller 192.168.1.30
            }
        }
        shared-network-name WLAN_Guest {
            authoritative disable
            subnet 192.168.3.0/24 {
                default-router 192.168.3.1
                dns-server 8.8.8.8
                dns-server 8.8.4.4
                lease 43200
                start 192.168.3.2 {
                    stop 192.168.3.254
                }
            }
        }
    }
    dns {
        forwarding {
            cache-size 150
            listen-on eth0
            listen-on eth2
        }
    }
    gui {
        https-port 443
    }
    nat {
        rule 5010 {
            outbound-interface pppoe0
            type masquerade
        }
    }
}
system {
    host-name %ROUTERHOSTNAME%
    login {
        user %USERNAME% {
            authentication {
                encrypted-password %ENCRYPTEDPASSWORD%
                plaintext-password ""
            }
            level admin
        }
    }
    ntp {
        server 0.ubnt.pool.ntp.org {
        }
        server 1.ubnt.pool.ntp.org {
        }
        server 2.ubnt.pool.ntp.org {
        }
        server 3.ubnt.pool.ntp.org {
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    time-zone UTC
}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:system@4:ubnt-pptp@1:ubnt-util@1:vrrp@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v1.8.5.4884695.160608.1104 */
