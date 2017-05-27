/*============================================================================*/
/*                                                                            */
/*    erpro8_soho-acl_config.boot                                             */
/*                                                                            */
/*    An enhanced and hardened SOHO EdgeRouter PRO (ERPro-8) configuration    */
/*    using an ACL style firewall.                                           */
/*                                                                            */
/*    This config.boot can be found on github at:                             */
/*                                                                            */
/*                                                                            */
/*    ========  USEFUL RESOURCES  ========                                    */
/*    ubnt edgerouter community forums:                                       */
/*    - https://community.ubnt.com/category/18/edgerouter                     */
/*                                                                            */
/*    ubnt edgemax knowledgebase:                                             */
/*    - https://help.ubnt.com/hc/en-us/categories/200321064-EdgeMAX           */
/*                                                                            */
/*    general edgeos configuration:                                           */
/*    - http://www.dahl-jacobsen.dk/tips/2015/04/29/Edgeos-configuration.html
/*    - https://blog.laslabs.com/2013/06/initial-configuration-ubiquiti-edgerouter-lite/
/*    - https://loganmarchione.com/2016/04/ubiquiti-edgerouter-lite-setup/
/*    - https://www.reddit.com/r/Ubiquiti/comments/33zkhu/useful_edgerouter_cli_commands_settings/
/*    - https://help.ubnt.com/hc/en-us/articles/205223460-EdgeRouter-System-Settings-Configuration
/*    - https://help.ubnt.com/hc/en-us/articles/205223500-EdgeRouter-SNMP
/*    - https://help.ubnt.com/hc/en-us/articles/115002531728-EdgeRouter-Beginners-Guide-to-EdgeRouter
/*    - https://networkjutsu.com/my-home-router-edgerouter-lite/              */
/*                                                                            */
/*    general edgeos firewall configuration:                                  */
/*    - https://github.com/didenko/er_poe_fw                                  */
/*    - https://community.ubnt.com/topic/187662/layman-s-firewall-explanation */
/*                                                                            */
/*    firewall the guest, IoT, & management vlans:                            */
/*    - https://help.ubnt.com/hc/en-us/articles/218889067-EdgeRouter-How-to-Protect-a-Guest-Network-on-EdgeRouter
/*    - https://community.ubnt.com/topic/111398/help-with-firewall-rules-for-a-vlan-guest-network
/*                                                                            */
/*    dhcp & dns configuration (incl DNSSEC validation)                       */
/*    - http://www.thekelleys.org.uk/dnsmasq/doc.html                         */
/*    - https://community.ubnt.com/topic/219592/dnssec-dnsmasq-with-edgerouter-1-8-5/14
/*    - https://community.ubnt.com/topic/109427/change-wan-dns-server         */
/*                                                                            */
/*    media streaming multicast (chromecast, sonos, etc)                      */
/*    - https://community.ubnt.com/topic/152600/multicast-sonos-phorus-play-fi-broadcast-255-255-255-255-port-discovery-solution-port/12
/*    - https://www.cron.dk/edgerouter-and-chromecast/                        */
/*    - https://community.ubnt.com/topic/119854/dlna-igmp-ssdp-multicast-between-routers
/*    - https://github.com/britannic/ubnt-bcast-relay                         */
/*    - https://community.ubnt.com/topic/291704/chromecast-and-airprint-across-subnets-vlans/4
/*    - https://help.ubnt.com/hc/en-us/articles/204961854-EdgeRouter-Set-up-IGMP-proxy-and-statistics
/*                                                                            */
/*    ad-bloccking & blacklisting:                                            */
/*    - https://community.ubnt.com/topic/170060/cli-integrated-dnsmasq-adblocking-blacklisting-v3-6-3-2-easy-config
/*                                                                            */
/*    edgeos security hardening:                                              */
/*    - https://www.manitonetworks.com/ubiquiti/                              */
/*                                                                            */
/*============================================================================*/
/*============================================================================*/

firewall {
    all-ping enable
    broadcast-ping disable
    conntrack-expect-table-size 2048
    conntrack-hash-size 4096
    conntrack-table-size 262144
    conntrack-tcp-loose enable
    group {
        network-group RFC1918-Private-Ranges {
            description "RFC 1918 Private Ranges"
            network 10.0.0.0/8
            network 172.16.0.0/12
            network 192.168.0.0/16
        }
        network-group IANA-Reserved-Ranges {
            description "IANA Reserved Ranges"
            network 0.0.0.0/8
            network 10.0.0.0/8
            network 100.64.0.0/10
            network 127.0.0.0/8
            network 169.254.0.0/16
            network 172.16.0.0/12
            network 192.0.0.0/24
            network 192.0.2.0/24
            network 192.168.0.0/16
            network 198.18.0.0/15
            network 198.51.100.0/24
            network 203.0.113.0/24
            network 224.0.0.0/4
            network 240.0.0.0/4
        }
    }
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians enable
    name WAN_IN {
        default-action drop
        enable-default-log
        description "incoming IPv4 traffic from the WAN"
        rule 50 {
            action accept
            description "allow all established & related IPv4 traffic incoming from the WAN"
            protocol all
            state {
                established enable
                related enable
            }
        }
    }
    name WAN_LOCAL {
        default-action drop
        enable-default-log
        description "drop all IPv4 traffic from the WAN to the router"
        /* allows the routers DNS server to to forward properly. this rule can */
        /* be deleted if using an external dns server */
        rule 20 {
            action accept
            description "allow DNS traffic from the WAN"
            destination {
                port 53
            }
            protocol udp
        }
        /* allow ntp */
        rule 30 {
            action accept
            description "allow NTP traffic from the WAN"
            destination {
                port 123
            }
            protocol udp
        }
    }
    name DMZ_IN {
        default-action drop
        enable-default-log
        description "incoming IPv4 traffic from the DMZ"
        rule 20 {
            action accept
            description "allow all established & related IPv4 traffic incoming from the DMZ"
            protocol all
            state {
                established enable
                related enable
            }
        }
    }
    name DMZ_LOCAL {
        default-action drop
        enable-default-log
        description "IPv4 traffic from the DMZ to the router"
        rule 20 {
            action accept
            description "allow DNS traffic from the DMZ"
            destination {
                port 53
            }
            protocol udp
        }
        rule 30 {
            action accept
            description "allow DHCP traffic from the DMZ"
            destination {
                port 67
            }
            protocol udp
        }
        rule 40 {
            action accept
            description "allow NTP traffic from the DMZ"
            destination {
                port 123
            }
            protocol udp
        }
    }
    name LAN_IN {
        default-action drop
        enable-default-log
        description "incoming IPv4 traffic from the LAN"
        rule 20 {
            action accept
            description "allow all established, new, & related IPv4 traffic incoming from LAN"
            protocol all
            state {
                established enable
                new enable
                related enable
            }
        }
    }
    name LAN_LOCAL {
        default-action drop
        enable-default-log
        description "IPv4 traffic from the LAN to the router"
        rule 20 {
            action accept
            description "allow DNS traffic from the LAN"
            destination {
                port 53
            }
            protocol udp
        }
        rule 30 {
            action accept
            description "allow DHCP traffic from the LAN"
            destination {
                port 67
            }
            protocol udp
        }
        rule 40 {
            action accept
            description "allow NTP traffic from the LAN"
            destination {
                port 123
            }
            protocol udp
        }
    }
    name GUEST_IN {
        default-action drop
        enable-default-log
        description "incoming IPv4 traffic from Guest_VLAN"
        rule 30 {
            action accept
            description "allow all established, new, & related IPv4 traffic from Guest_VLAN to WAN"
            destination {
                interface eth0
            }
            protocol all
            state {
                established enable
                new enable
                related enable
            }
        }
    }
    name GUEST_LOCAL {
        default-action drop
        enable-default-log
        description "IPv4 traffic from the Guest_VLAN to router"
        rule 20 {
            action accept
            description "allow DNS traffic from the Guest_VLAN"
            destination {
                port 53
            }
            protocol udp
        }
        rule 30 {
            action accept
            description "allow DHCP traffic from the Guest_VLAN"
            destination {
                port 67
            }
            protocol udp
        }
        rule 40 {
            action accept
            description "allow NTP traffic from the Guest_VLAN"
            destination {
                port 123
            }
            protocol udp
        }
    }
    name MANAGEMENT_IN {
        default-action drop
        enable-default-log
        description "incoming IPv4 traffic from the Management_VLAN"
        rule 20 {
            action accept
            description "allow all established, new, & related IPv4 traffic from the Management_VLAN to the LAN & IoT_VLAN"
            destination {
                network 192.168.0.0/16
            }
            protocol all
            state {
                established enable
                new enable
                related enable
            }
        }
    }
    name MANAGEMENT_LOCAL {
        default-action drop
        enable-default-log
        description "IPv4 traffic from the Management_VLAN to the router"
        rule 20 {
            action accept
            description "allow DNS traffic from the Management_VLAN"
            destination {
                port 53
            }
            protocol udp
        }
        rule 30 {
            action accept
            description "allow DHCP traffic from the Management_VLAN"
            destination {
                port 67
            }
            protocol udp
        }
        rule 40 {
            action accept
            description "allow ICMP traffic from the Management_VLAN"
            protocol icmp
        }
        rule 50 {
            action accept
            description "allow SNMP traffic from the Management_VLAN"
            destination {
                port 161
            }
            protocol udp
        }
        rule 60 {
            action accept
            description "allow SSH traffic from the Management_VLAN"
            destination {
                port 22
            }
            protocol tcp
        }
        rule 70 {
            action accept
            description "allow HTTPS traffic from the Management_VLAN"
            destination {
                port 443
            }
            protocol tcp
        }
        rule 80 {
            action accept
            description "allow NTP traffic from the Management_VLAN"
            destination {
                port 123
            }
            protocol udp
        }
        rule 90 {
            action accept
            description "allow all established & related traffic from Management_VLAN"
            protocol all
            state {
                established enable
                related enable
            }
        }
    }
    name IOT_IN {
        default-action drop
        enable-default-log
        description "incoming IPv4 traffic from IoT_VLAN"
        rule 20 {
            action accept
            description "allow all established & related IPv4 traffic incoming from IoT_VLAN"
            protocol all
            state {
                established enable
                related enable
            }
        }
    }
    name IOT_LOCAL {
        default-action drop
        enable-default-log
        description "IPv4 traffic from the IoT_VLAN to the router"
        rule 20 {
            action accept
            description "allow DNS traffic from the IoT_VLAN"
            destination {
                port 53
            }
            protocol udp
        }
        rule 30 {
            action accept
            description "allow DHCP traffic from the IoT_VLAN"
            destination {
                port 67
            }
            protocol udp
        }
        rule 40 {
            action accept
            description "allow NTP traffic from the IoT_VLAN"
            destination {
                port 123
            }
            protocol udp
        }
    }
    name IOT_OUT {
        default-action accept
        description "outgoing IPv4 traffic to IoT_VLAN"
        rule 10 {
            action drop
            description "drop all invalid IPv4 traffic outgoing to the IoT_VLAN"
            protocol all
            state {
                invalid enable
            }
        }
        /* drop TELNET traffic outgoing to the IoT_VLAN to hinder IoT botnets */
        rule 20 {
            action drop
            description "drop TELNET traffic outgoing to the IoT_VLAN"
            log enable
            destination {
                port 23,2323
            }
            protocol tcp
        }
        /* drop SSH traffic outgoing to the IoT_VLAN to hinder IoT botnets */
        rule 30 {
            action drop
            description "drop SSH traffic outgoing to the IoT_VLAN"
            log enable
            destination {
                port 22
            }
            protocol tcp
        }
        /* drop TR-069 traffic outgoing to the IoT_VLAN to hinder IoT botnets */
        rule 40 {
            action drop
            description "drop TR-069 traffic outgoing to the IoT_VLAN"
            log enable
            destination {
                port 7547
            }
            protocol tcp
        }
        /* drop FTP traffic outgoing to the IoT_VLAN to hinder IoT botnets */
        rule 50 {
            action drop
            description "drop FTP traffic outgoing to the IoT_VLAN"
            log enable
            destination {
                port 20,21
            }
            protocol tcp
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
    ethernet eth0 {
        description "WAN (ISP_PPPoE)"
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
            name-server no-update
            password %PPPOEPASSWORD%
            user-id %PPPOEUSERNAME%
        }
        speed auto
    }
    ethernet eth1 {
        disable
    }
    ethernet eth2 {
        disable
    }
    ethernet eth3 {
        disable
    }
    ethernet eth4 {
        address 10.20.30.41/24
        description "DMZ"
        firewall {
            in {
                name DMZ_IN
            }
            local {
                name DMZ_LOCAL
            }
        }
        duplex auto
        speed auto
    }
    ethernet eth5 {
        disable
    }
    ethernet eth6 {
        disable
    }
    ethernet eth7 {
        address 192.168.1.1/24
        description "LAN"
        firewall {
            in {
                name LAN_IN
            }
            local {
                name LAN_LOCAL
            }
        }
        mtu 1500
        duplex auto
        speed auto
        vif 20 {
            address 192.168.20.1/24
            description "Management VLAN"
            firewall {
                in {
                    name MANAGEMENT_IN
                }
                local {
                    name MANAGEMENT_LOCAL
                }
            }
            mtu 1500
        }
        vif 30 {
            address 192.168.30.1/24
            description "IoT VLAN"
            firewall {
                in {
                    name IOT_IN
                }
                local {
                    name IOT_LOCAL
                }
                out {
                    name IOT_OUT
                }
            }
            mtu 1500
        }
        vif 200 {
            address 172.16.200.1/24
            description "Guest VLAN"
            firewall {
                in {
                    name GUEST_IN
                }
                local {
                    name GUEST_LOCAL
                }
            }
            mtu 1500
        }
    }
    loopback lo {
    }
}
service {
    dhcp-server {
        disabled false
        hostfile-update disable
        shared-network-name DMZ_DHCP {
            authoritative enable
            description "DMZ DHCP pool"
            subnet 10.20.30.0/24 {
                default-router 10.20.30.41
                dns-server 10.20.30.41
                ntp-server 10.20.30.41
                lease 43200
                start 10.20.30.70 {
                    stop 10.20.30.74
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 10.20.30.42
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 10.20.30.43
                    mac-address xx:xx:xx:xx:xx:xx
                }
            }
        }
        shared-network-name LAN_DHCP {
            authoritative enable
            description "LAN DHCP pool"
            subnet 192.168.1.0/24 {
                default-router 192.168.1.1
                dns-server 192.168.1.1
                ntp-server 192.168.1.1
                lease 86400
                start 192.168.1.100 {
                    stop 192.168.1.164
                }
                static-mapping UC-CK {
                    ip-address 192.168.1.2
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping UAP-AC-HD {
                    ip-address 192.168.1.3
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.1.4
                    mac-address xx:xx:xx:xx:xx:xx
                }
                unifi-controller 192.168.1.2
            }
        }
        shared-network-name Management_VLAN_DHCP {
            authoritative enable
            description "Management VLAN DHCP pool"
            subnet 192.168.20.0/24 {
                default-router 192.168.20.1
                dns-server 192.168.20.1
                ntp-server 192.168.20.1
                lease 43200
                start 192.168.20.20 {
                    stop 192.168.20.28
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.20.x
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.20.x
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.20.x
                    mac-address xx:xx:xx:xx:xx:xx
                }
            }
        }
        shared-network-name IoT_VLAN_DHCP {
            authoritative enable
            description "IoT VLAN DHCP pool"
            subnet 192.168.30.0/24 {
                default-router 192.168.30.1
                dns-server 192.168.30.1
                ntp-server 192.168.30.1
                lease 43200
                start 192.168.30.30 {
                    stop 192.168.30.46
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.30.x
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.30.x
                    mac-address xx:xx:xx:xx:xx:xx
                }
                static-mapping %DEVICEHOSTNAME% {
                    ip-address 192.168.30.x
                    mac-address xx:xx:xx:xx:xx:xx
                }
            }
        }
        shared-network-name Guest_VLAN_DHCP {
            authoritative enable
            description "Guest VLAN DHCP pool"
            subnet 172.16.200.0/24 {
                default-router 172.16.200.1
                dns-server 172.16.200.1
                ntp-server 172.16.200.1
                lease 43200
                start 172.16.200.200 {
                    stop 172.16.200.232
                }
            }
        }
    }
    dns {
        forwarding {
            cache-size 512
            listen-on eth4
            listen-on eth7
            listen-on eth7.20
            listen-on eth7.30
            listen-on eth7.200
            name-server 8.8.8.8
            name-server 8.8.4.4
            system
            options dnssec
            options trust-anchor=,19036,8,2,49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
            options trust-anchor=,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
            options dnssec-check-unsigned
        }
    }
    gui {
        listen-address 192.168.20.1
        older-ciphers disable
        https-port 443
    }
    nat {
        rule 5010 {
            description "outbound WAN NAT masquerade"
            log disable
            outbound-interface pppoe0
            protocol all
            type masquerade
        }
    }
    snmp {
        location "%LOCATION%"
        description "%DESCRIPTION%"
        contact "%CONTACT%"
        community %COMMUNITY%
        community %COMMUNITY% authorization ro
        community public client 192.168.10.0/24
        listen-address 192.168.10.1
    }
    ssh {
        protocol-version v2
        port 22
        listen-address 192.168.20.1
    }
}
system {
    host-name %ROUTERHOSTNAME%
    login {
        user %USERNAME1% {
            full name "%FULLNAME1%"
            authentication {
                plaintext-password "%USER1PASS%"
            }
            level admin
        }
        user %USERNAME2% {
            full name "%FULLNAME2%"
            authentication {
                plaintext-password "%USER2PASS%"
            }
            level admin
        }
        banner {
            pre-login "\n\n\n\tUNAUTHORIZED USE OF THIS SYSTEM\n\tIS STRICTLY PROHIBITED! THIS\n\tDEVICE IS MONITORED, INCLUDING\n\tACCESS ATTEMPTS AND LOGINS.\n\n\tACCESS ONLY AUTHORIZED TO NETWORK STAFF.\n\n\tPlease contact "username1@domain.tld" for\n\tauthorization if you need access to this equipment.\n\n\n"
            post-login "---THIS DEVICE IS MONITORED, AND ACCESS IS REGULARLY AUDITED---"
        }
    }
    name-server 127.0.0.1
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
    offload {
        ipv4 {
            forwarding enable
            gre enable
            pppoe enable
            vlan enable
        }
        ipv6 {
            forwarding enable
            pppoe enable
            vlan enable
        }
        ipsec enable
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
    time-zone US/Mountain
    traffic-analysis {
        dpi enable
        export enable
    }
}

/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:system@4:ubnt-pptp@1:ubnt-util@1:vrrp@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v1.8.5.4884695.160608.1104 */
