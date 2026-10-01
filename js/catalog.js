/* catalog.js — catalogue des équipements simulés avec leurs caractéristiques (fiches produits).
   ok:true  = valeurs relevées sur fiche constructeur (voir "source")
   ok:false = valeurs typiques/indicatives (à vérifier sur la fiche du produit réel utilisé en classe) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};

const grp = (label, tag, models) => ({ label, tag, models });
const C = {};

/* ---------------------------------------------------------------- Postes de travail */
C['pc-win'] = { cat: 'Postes', label: 'PC Windows 11', short: 'PC', kind: 'host', os: 'windows', icon: 'pc', vendor: 'Dell', oui: 'dell', prefix: 'PC',
  ports: [{ name: 'Ethernet0', short: 'Eth0', speed: 1000 }], ok: false,
  specs: [['Système', 'Windows 11 Pro (invite de commandes en français)'], ['Interface réseau', '1 × Gigabit Ethernet 10/100/1000 RJ45'], ['TTL par défaut', '128'], ['Commandes', 'ipconfig, ping, tracert, nslookup, arp, netstat, route, curl, telnet, hostname'], ['Pare-feu', 'Réponse au ping activable/désactivable'], ['Rôle en TP', 'Poste client (DHCP ou IP statique)']],
  tags: ['Adressage IPv4', 'DHCP client', 'DNS client', 'ARP', 'ICMP'] };
C['pc-linux'] = { cat: 'Postes', label: 'PC Linux (Debian/Ubuntu)', short: 'PC Linux', kind: 'host', os: 'linux', icon: 'pc', vendor: 'Générique', oui: 'lenovo', prefix: 'LX',
  ports: [{ name: 'ens33', short: 'ens33', speed: 1000 }], ok: false,
  specs: [['Système', 'Debian / Ubuntu Desktop (shell bash simplifié)'], ['Interface réseau', '1 × Gigabit Ethernet ens33'], ['TTL par défaut', '64'], ['Commandes', 'ip a, ip r, ip neigh, ping, traceroute, dig/nslookup, curl, telnet, hostname, ss'], ['Rôle en TP', 'Poste client / administration']],
  tags: ['Adressage IPv4', 'Ligne de commande Linux', 'ARP', 'ICMP'] };
C['laptop'] = { cat: 'Postes', label: 'Ordinateur portable', short: 'Portable', kind: 'host', os: 'windows', icon: 'laptop', vendor: 'HP', oui: 'hp', prefix: 'PORT',
  ports: [{ name: 'Ethernet0', short: 'Eth0', speed: 1000 }, { name: 'Wi-Fi', short: 'Wi-Fi', speed: 300, media: 'wifi', kind: 'wifi' }], wifi: true, ok: false,
  specs: [['Système', 'Windows 11 Pro'], ['Interfaces réseau', '1 × Ethernet 1 Gb/s + 1 × Wi-Fi 6 (802.11ax)'], ['TTL par défaut', '128'], ['Sans-fil', 'SSID + clé WPA2/WPA3 à saisir dans l\'onglet Configuration'], ['Rôle en TP', 'Poste mobile, accès Wi-Fi']],
  tags: ['Wi-Fi', 'Adressage IPv4', 'DHCP client'] };

/* ---------------------------------------------------------------- Serveurs */
C['srv-linux'] = { cat: 'Serveurs', label: 'Serveur Linux (Debian 12)', short: 'Serveur', kind: 'host', os: 'linux', icon: 'server', vendor: 'Dell', oui: 'dell', prefix: 'SRV', server: true,
  ports: [{ name: 'ens33', short: 'ens33', speed: 1000 }], ok: false,
  specs: [['Système', 'Debian 12 « bookworm »'], ['Interface réseau', '1 × Gigabit Ethernet'], ['Services simulés', 'DHCP (isc-dhcp), DNS (bind9), HTTP/HTTPS (Apache), FTP*'], ['TTL par défaut', '64'], ['Rôle en TP', 'Serveur DHCP / DNS / Web']],
  tags: ['DHCP serveur', 'DNS', 'HTTP/HTTPS', 'Services réseau'] };
C['srv-win'] = { cat: 'Serveurs', label: 'Serveur Windows Server 2022', short: 'Serveur Win', kind: 'host', os: 'windows', icon: 'server', vendor: 'Dell', oui: 'dell', prefix: 'SRV', server: true,
  ports: [{ name: 'Ethernet0', short: 'Eth0', speed: 1000 }], ok: false,
  specs: [['Système', 'Windows Server 2022'], ['Interface réseau', '1 × Gigabit Ethernet'], ['Services simulés', 'DHCP, DNS, IIS (HTTP/HTTPS)'], ['TTL par défaut', '128'], ['Rôle en TP', 'Serveur DHCP / DNS / Web (bloc 2 SISR)']],
  tags: ['DHCP serveur', 'DNS', 'HTTP/HTTPS', 'Services réseau'] };
C['nas'] = { cat: 'Serveurs', label: 'NAS Synology DS223', short: 'NAS', kind: 'host', os: 'linux', icon: 'nas', vendor: 'Synology', oui: 'synology', prefix: 'NAS', server: true,
  ports: [{ name: 'LAN1', short: 'LAN1', speed: 1000 }], ok: true, source: 'synology.com — fiche DS223',
  specs: [['Baies', '2 × 3,5"/2,5" SATA'], ['Processeur', 'Realtek RTD1619B, 4 cœurs 1,7 GHz'], ['Mémoire', '2 Go DDR4 non extensible'], ['Réseau', '1 × Gigabit Ethernet RJ45'], ['Système', 'DSM (base Linux)'], ['Rôle en TP', 'Stockage, sauvegarde, partage de fichiers']],
  tags: ['Stockage', 'Sauvegarde'] };
C['printer'] = { cat: 'Serveurs', label: 'Imprimante réseau', short: 'Imprimante', kind: 'host', os: 'linux', icon: 'printer', vendor: 'Canon', oui: 'canon', prefix: 'IMP', peripheral: true,
  ports: [{ name: 'LAN', short: 'LAN', speed: 100 }], ok: false,
  specs: [['Interface réseau', '1 × Fast Ethernet 10/100'], ['Protocoles', 'IPP, LPD, RAW 9100, SNMP, HTTP (administration)'], ['Adressage', 'IP statique recommandée (réservation DHCP)'], ['Rôle en TP', 'Périphérique réseau, réservation DHCP']],
  tags: ['Adressage IPv4', 'DHCP'] };
C['ipphone'] = { cat: 'Serveurs', label: 'Téléphone IP Yealink T31P', short: 'Tél. IP', kind: 'host', os: 'linux', icon: 'phone', vendor: 'Yealink', oui: 'yealink', prefix: 'TEL', peripheral: true,
  ports: [{ name: 'Internet', short: 'Internet', speed: 100 }, { name: 'PC', short: 'PC', speed: 100 }], phone: true, ok: true, source: 'yealink.com — fiche T31P',
  specs: [['Ports réseau', '2 × 10/100 Mb/s (Internet PoE + PC) : le port PC relie un poste derrière le téléphone'], ['Alimentation', 'PoE 802.3af ou adaptateur'], ['Protocole', 'SIP'], ['Rôle en TP', 'VoIP, VLAN voix']],
  tags: ['VoIP', 'VLAN', 'PoE'] };

/* ---------------------------------------------------------------- Commutateurs */
const fa = (n, s) => ({ prefix: 'FastEthernet0/', short: 'Fa0/', n, start: 1, speed: 100 });
const gi = (n, s) => ({ prefix: 'GigabitEthernet0/', short: 'Gi0/', n, start: s || 1, speed: 1000 });
C['sw-2960'] = { cat: 'Commutateurs', label: 'Cisco Catalyst 2960-24TT', short: 'Cat 2960', kind: 'switch', icon: 'switch', vendor: 'Cisco', oui: 'cisco', prefix: 'SW', managed: true, l3: false,
  portGroups: [fa(24), gi(2)], ok: true, source: 'cisco.com — fiche Catalyst 2960 (WS-C2960-24TT-L)',
  specs: [['Ports', '24 × 10/100 Mb/s RJ45 + 2 × 10/100/1000 (liaisons montantes)'], ['Bande passante de commutation', '16 Gb/s'], ['Débit de transfert', '6,5 Mpps (paquets de 64 octets)'], ['VLAN', '255 VLAN supportés (ID 1–4094)'], ['Table MAC', '8 192 adresses (typique)'], ['Mémoire DRAM', '16 Mo'], ['Couche', 'Layer 2 (commutation)'], ['Fonctions', '802.1Q, STP/PVST/RSTP, Port Security, ACL L2–L4, DHCP snooping, DAI, 802.1X, CLI Cisco IOS'], ['Rôle en TP', 'Commutateur d\'accès, VLAN, trunk, STP, port-security']],
  macTableSize: 8192,
  tags: ['VLAN', 'Trunk 802.1Q', 'STP', 'Port-security', 'CLI IOS'] };
C['sw-3560'] = { cat: 'Commutateurs', label: 'Cisco Catalyst 3560-24PS (L3)', short: 'Cat 3560', kind: 'switch', icon: 'switchl3', vendor: 'Cisco', oui: 'cisco', prefix: 'SW', managed: true, l3: true,
  portGroups: [fa(24), gi(2)], ok: false, source: 'valeurs typiques — vérifier la fiche Cisco du modèle exact',
  specs: [['Ports', '24 × 10/100 Mb/s PoE (802.3af) + 2 × Gigabit (SFP sur le modèle réel, simulés en RJ45 : Gi0/1–2)'], ['Couche', 'Layer 3 : routage IPv4 inter-VLAN (SVI, ports routés)'], ['Routage', 'Statique, RIP, OSPF (IP Services)'], ['VLAN', '255 VLAN supportés'], ['Table MAC', '8 192 adresses (typique)'], ['Fonctions', '802.1Q, STP/RSTP, ACL, port-security, PoE'], ['Rôle en TP', 'Routage inter-VLAN, cœur de réseau de site']],
  macTableSize: 8192,
  tags: ['VLAN', 'Routage inter-VLAN', 'Commutateur L3', 'ACL'] };
C['sw-8p'] = { cat: 'Commutateurs', label: 'Switch 8 ports Gigabit non manageable', short: 'Switch 8p', kind: 'switch', icon: 'switch', vendor: 'Générique', oui: 'netgear', prefix: 'SW', managed: false, l3: false,
  portGroups: [{ prefix: 'Port', short: 'P', n: 8, start: 1, speed: 1000 }], ok: false,
  specs: [['Ports', '8 × 10/100/1000 Mb/s RJ45 (Auto-MDIX)'], ['Capacité de commutation', '16 Gb/s (typique)'], ['Table MAC', '4 K adresses (typique)'], ['Gestion', 'Aucune (plug and play) : pas de VLAN, pas de STP'], ['Rôle en TP', 'Réseau local simple ; illustre l\'absence de STP (boucle = tempête de broadcast) et la saturation de table MAC']],
  macTableSize: 4096,
  tags: ['Commutation', 'Table MAC'] };
C['sw-os6400'] = { cat: 'Commutateurs', label: 'Alcatel-Lucent OmniSwitch 6400-P48 (L3)', short: 'OS6400-P48', kind: 'switch', icon: 'switchl3', vendor: 'Alcatel-Lucent', oui: 'alcatel', prefix: 'OS', managed: true, l3: true, aos: true,
  portGroups: [{ prefix: '1/', short: '1/', n: 48, start: 1, speed: 1000 }], ok: true, source: 'Alcatel-Lucent OmniSwitch 6400 Series Hardware User Guide (OS6400-P48) — valeurs de la fiche ; comportement CLI AOS 6.4 reconstitué',
  specs: [['Ports', '44 × RJ-45 10/100/1000 PoE + 4 ports combo (10/100/1000 ou SFP 1000BASE-X) — simulés 1/1 à 1/48 en RJ-45'], ['Empilage', '2 ports dédiés 10 Gb/s (non simulé)'], ['Budget PoE', '240 W (bloc 360 W) ou 390 W (bloc 510 W) ; bloc 510 W fourni avec le châssis'], ['Capacité de commutation', '96 Gb/s full-duplex (192 Gb/s cumulés) — 71,4 Mpps'], ['Table MAC', 'jusqu\'à 16 000 adresses'], ['Dimensions', '44 cm × 27 cm × 4,4 cm (1U), 4,50 kg (châssis seul)'], ['Système', 'AOS (Alcatel-Lucent Operating System) — CLI sans mode enable/configure ; invite « -> »'], ['Couche', 'Layer 3 : interfaces IP par VLAN, routes statiques (routage dynamique non simulé sur ce modèle)'], ['Rôle en TP', 'Cœur/accès de réseau d\'établissement, VLAN, agrégation LACP, PoE téléphonie IP']],
  macTableSize: 16000,
  tags: ['VLAN', 'PoE', 'LACP', 'AOS', 'Alcatel-Lucent'] };
C['hub'] = { cat: 'Commutateurs', label: 'Concentrateur (hub) 4 ports', short: 'Hub', kind: 'hub', icon: 'hub', vendor: 'Générique', oui: 'netgear', prefix: 'HUB',
  portGroups: [{ prefix: 'Port', short: 'P', n: 4, start: 1, speed: 10 }], ok: false,
  specs: [['Ports', '4 × 10 Mb/s Ethernet (half-duplex)'], ['Fonctionnement', 'Répéteur couche 1 : la trame est répétée sur tous les autres ports (domaine de collision unique)'], ['Rôle en TP', 'Comparer hub / switch avec l\'analyseur de trames (tout le monde voit tout)']],
  tags: ['Couche 1', 'Domaine de collision', 'Analyse de trames'] };

/* ---------------------------------------------------------------- Routeurs */
C['r-1941'] = { cat: 'Routeurs', label: 'Cisco ISR 1941', short: 'Cisco 1941', kind: 'router', icon: 'router', vendor: 'Cisco', oui: 'cisco', prefix: 'R', os: 'ios',
  portGroups: [{ prefix: 'GigabitEthernet0/', short: 'Gi0/', n: 2, start: 0, speed: 1000 }], ok: true, source: 'cisco.com — fiche Cisco 1900 Series ISR',
  specs: [['Ports fixes', '2 × Gigabit Ethernet 10/100/1000 (RJ45)'], ['Emplacements', '2 × EHWIC (1 double largeur possible)'], ['Mémoire DRAM', '512 Mo par défaut, 2 Go max.'], ['Mémoire Flash', '256 Mo par défaut, 4 Go max. (2 emplacements)'], ['Débit agrégé (services simultanés)', '25 à 150 Mb/s (selon licence)'], ['Alimentation', 'AC / PoE, 110 W max.'], ['Format', '2 U rack'], ['Système', 'Cisco IOS 15.x'], ['Rôle en TP', 'Routeur de site : routage statique/RIP, NAT/PAT, DHCP, ACL, sous-interfaces 802.1Q']],
  tags: ['Routage statique', 'RIP', 'NAT/PAT', 'ACL', 'DHCP', 'CLI IOS'] };
C['r-2911'] = { cat: 'Routeurs', label: 'Cisco ISR 2911', short: 'Cisco 2911', kind: 'router', icon: 'router', vendor: 'Cisco', oui: 'cisco', prefix: 'R', os: 'ios',
  portGroups: [{ prefix: 'GigabitEthernet0/', short: 'Gi0/', n: 3, start: 0, speed: 1000 }], ok: true, source: 'cisco.com — fiche Cisco 2900 Series ISR',
  specs: [['Ports fixes', '3 × Gigabit Ethernet 10/100/1000 (RJ45)'], ['Emplacements', '4 × EHWIC, 1 module de service (SM), 1 ISM, 2 PVDM'], ['Mémoire DRAM', '512 Mo par défaut (DDR2 ECC), 2 Go max.'], ['Mémoire Flash', '256 Mo par défaut (CompactFlash), 4 Go max.'], ['Débit agrégé (services simultanés)', 'jusqu\'à 75 Mb/s'], ['Alimentation', 'AC, PoE ou DC ; RPS 2300 externe possible'], ['Système', 'Cisco IOS 15.x'], ['Rôle en TP', 'Routeur de site / d\'agence à 3 réseaux (LAN, DMZ, WAN)']],
  tags: ['Routage statique', 'RIP', 'NAT/PAT', 'ACL', 'DHCP', 'CLI IOS'] };
C['r-4321'] = { cat: 'Routeurs', label: 'Cisco ISR 4321', short: 'Cisco 4321', kind: 'router', icon: 'router', vendor: 'Cisco', oui: 'cisco', prefix: 'R', os: 'ios',
  portGroups: [{ prefix: 'GigabitEthernet0/0/', short: 'Gi0/0/', n: 2, start: 0, speed: 1000 }], ok: false, source: 'valeurs typiques — vérifier la fiche Cisco ISR 4300',
  specs: [['Ports fixes', '2 × Gigabit Ethernet (RJ45/SFP combo)'], ['Emplacements', '2 × NIM'], ['Débit agrégé', '50 à 100 Mb/s (extensible par licence)'], ['Système', 'Cisco IOS XE'], ['Rôle en TP', 'Routeur d\'agence nouvelle génération']],
  tags: ['Routage statique', 'NAT/PAT', 'CLI IOS'] };
C['inet'] = { cat: 'Routeurs', label: 'Internet (routeur FAI)', short: 'Internet', kind: 'router', icon: 'cloud', vendor: 'FAI', oui: 'cisco', prefix: 'ISP', os: 'ios',
  portGroups: [{ prefix: 'GigabitEthernet0/', short: 'Gi0/', n: 6, start: 0, speed: 1000 }], ok: false,
  specs: [['Ports', '6 × Gigabit Ethernet'], ['Fonctionnement', 'Routeur d\'opérateur : à relier aux WAN de vos sites. Ajoutez-y des routes vers les adresses publiques (ou un routage RIP).'], ['Astuce', 'Placez derrière un serveur DNS/Web « public » pour simuler Internet.'], ['Rôle en TP', 'Simuler l\'Internet / le FAI']],
  tags: ['WAN', 'NAT/PAT', 'Adresses publiques'] };
C['box'] = { cat: 'Routeurs', label: 'Box FAI (routeur/NAT/DHCP)', short: 'Box', kind: 'box', icon: 'box', vendor: 'Orange', oui: 'orange', prefix: 'BOX', l3: true, managed: false,
  portGroups: [{ prefix: 'LAN', short: 'LAN', n: 4, start: 1, speed: 1000 }, { prefix: 'WAN', short: 'WAN', n: 1, start: 0, speed: 1000, nonum: true }], ok: false,
  specs: [['Ports', '4 × Gigabit LAN + 1 × WAN'], ['Configuration usine', 'LAN 192.168.1.1/24, serveur DHCP (192.168.1.10–.100), NAT/PAT vers le WAN (DHCP)'], ['Fonctions', 'Routeur domestique : NAT, DHCP, DNS relais, pare-feu basique'], ['Rôle en TP', 'Accès Internet d\'un particulier / d\'une TPE']],
  tags: ['NAT/PAT', 'DHCP', 'Réseau domestique'] };

/* ---------------------------------------------------------------- Sécurité */
C['fw-sn210'] = { cat: 'Sécurité', label: 'Stormshield SN210', short: 'SN210', kind: 'firewall', icon: 'firewall', vendor: 'Stormshield', oui: 'stormshield', prefix: 'FW', fwStyle: 'stormshield',
  ports: [{ name: 'out', short: 'OUT', speed: 1000, zone: 'WAN' }, { name: 'in', short: 'IN', speed: 1000, zone: 'LAN' }, { name: 'dmz1', short: 'DMZ1', speed: 1000, zone: 'DMZ' }, { name: 'dmz2', short: 'DMZ2', speed: 1000, zone: 'DMZ2' }],
  defaults: { out: { dhcp: true }, in: { ip: '192.168.1.254', mask: '255.255.255.0' }, dmz1: { ip: '172.16.0.254', mask: '255.255.255.0' } },
  ok: true, source: 'stormshield.com — fiche produit SN210',
  specs: [['Interfaces', '2 + 6 ports 1000BASE-T (commutateur intégré) — le simulateur en expose 4 : OUT, IN, DMZ1, DMZ2'], ['Débit firewall', '2 Gb/s (UDP 1518 octets), 1 Gb/s IMIX'], ['Débit IPS', '1,6 Gb/s'], ['VPN IPsec (AES-GCM256)', '148 Mb/s'], ['Connexions simultanées', '200 000'], ['Tunnels IPsec max.', '50'], ['Clients VPN SSL simultanés', '20'], ['Filtrage', 'Politique de filtrage ordonnée + NAT (masquerade, redirection)'], ['Rôle en TP', 'Pare-feu de site : zones LAN / DMZ / WAN, filtrage, NAT, redirection de port']],
  tags: ['Pare-feu', 'DMZ', 'NAT', 'Filtrage', 'VPN IPsec'] };
C['fw-fgt60f'] = { cat: 'Sécurité', label: 'Fortinet FortiGate 60F', short: 'FG-60F', kind: 'firewall', icon: 'firewall', vendor: 'Fortinet', oui: 'fortinet', prefix: 'FW', fwStyle: 'fortinet',
  ports: [{ name: 'wan1', short: 'wan1', speed: 1000, zone: 'WAN' }, { name: 'wan2', short: 'wan2', speed: 1000, zone: 'WAN' }, { name: 'dmz', short: 'dmz', speed: 1000, zone: 'DMZ' }, { name: 'internal1', short: 'int1', speed: 1000, zone: 'LAN' }, { name: 'internal2', short: 'int2', speed: 1000, zone: 'LAN' }, { name: 'internal3', short: 'int3', speed: 1000, zone: 'LAN' }],
  defaults: { wan1: { dhcp: true }, internal1: { ip: '192.168.1.99', mask: '255.255.255.0' }, dmz: { ip: '10.10.10.254', mask: '255.255.255.0' } },
  ok: true, source: 'fortinet.com — fiche FortiGate/FortiWiFi 60F',
  specs: [['Interfaces', '10 × GE RJ45 (2 WAN, 1 DMZ, 7 internes) — le simulateur en expose 6'], ['Débit firewall', '10 Gb/s'], ['Débit IPS', '1,4 Gb/s'], ['Débit NGFW', '1 Gb/s'], ['Filtrage', 'Politiques IPv4 (interface entrante → sortante), NAT par politique'], ['Rôle en TP', 'Pare-feu UTM de PME (SISR bloc 3)']],
  tags: ['Pare-feu', 'DMZ', 'NAT', 'UTM'] };
C['fw-pfsense'] = { cat: 'Sécurité', label: 'pfSense (Netgate 1100)', short: 'pfSense', kind: 'firewall', icon: 'firewall', vendor: 'Netgate', oui: 'netgate', prefix: 'FW', fwStyle: 'pfsense',
  ports: [{ name: 'WAN', short: 'WAN', speed: 1000, zone: 'WAN' }, { name: 'LAN', short: 'LAN', speed: 1000, zone: 'LAN' }, { name: 'OPT1', short: 'OPT1', speed: 1000, zone: 'DMZ' }],
  defaults: { WAN: { dhcp: true }, LAN: { ip: '192.168.1.1', mask: '255.255.255.0' } },
  ok: false, source: 'valeurs typiques — vérifier la fiche Netgate 1100',
  specs: [['Interfaces', '3 × GbE (WAN, LAN, OPT1)'], ['Matériel', 'ARM Cortex-A53 double cœur, 1 Go RAM, 8 Go eMMC'], ['Système', 'pfSense Plus (FreeBSD)'], ['Filtrage', 'Règles par interface (pf), NAT sortant automatique, redirections de ports'], ['Rôle en TP', 'Pare-feu libre — très utilisé en BTS SIO']],
  tags: ['Pare-feu', 'DMZ', 'NAT', 'Logiciel libre'] };

/* ---------------------------------------------------------------- Sans-fil */
C['ap-u6'] = { cat: 'Sans-fil', label: 'Borne Wi-Fi UniFi U6 Lite', short: 'AP U6', kind: 'ap', managed: false, icon: 'ap', vendor: 'Ubiquiti', oui: 'ubiquiti', prefix: 'AP',
  ports: [{ name: 'Eth0', short: 'Eth0', speed: 1000 }, { name: 'Radio', short: 'Radio', speed: 1200, media: 'wifi', kind: 'radio' }], ok: true, source: 'ui.com — fiche UniFi U6 Lite',
  specs: [['Standard', 'Wi-Fi 6 (802.11ax), 2×2 MIMO'], ['Débit radio', '300 Mb/s (2,4 GHz) + 1 200 Mb/s (5 GHz)'], ['Port réseau', '1 × Gigabit Ethernet, PoE 802.3af'], ['Sécurité', 'WPA2/WPA3, SSID multiples, VLAN par SSID'], ['Rôle en TP', 'Point d\'accès : SSID, clé, association des portables']],
  tags: ['Wi-Fi', 'SSID', 'WPA2', 'PoE'] };

/* Ordre d'affichage des catégories */
const ORDER = ['Postes', 'Serveurs', 'Commutateurs', 'Routeurs', 'Sécurité', 'Sans-fil'];
NS.CATALOG = C; NS.CAT_ORDER = ORDER;
NS.CABLES = [
  { id: 'auto', label: 'Câble (auto)', desc: 'Choisit droit ou croisé selon les équipements' },
  { id: 'straight', label: 'Câble droit', desc: 'PC↔switch, switch↔routeur' },
  { id: 'cross', label: 'Câble croisé', desc: 'PC↔PC, switch↔switch, PC↔routeur' },
  { id: 'fiber', label: 'Fibre optique', desc: 'Ports SFP/fibre uniquement' },
];
})(typeof window !== 'undefined' ? window : globalThis);
