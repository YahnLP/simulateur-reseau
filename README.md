# Simulateur Réseau — Bac Pro CIEL / BTS SIO SISR

Créé par Yahn LE PRETTRE — Formaxion Landes

Simulateur réseau pédagogique hors-ligne, type Filius/Packet Tracer, avec analyseur de trames intégré (type Wireshark). Aucun serveur, aucune installation : ouvrez `index.html` (ou le fichier autonome `dist/simulateur-reseau.html`) dans Chrome/Edge/Firefox.

## Fonctionnalités

- **Topologie libre** : palette d'équipements, câbles (droit/croisé/fibre), Wi-Fi ; postes Windows/Linux, serveurs, switches Cisco (CLI IOS) et Alcatel-Lucent OmniSwitch (CLI AOS), routeurs Cisco, pare-feu (Stormshield/FortiGate/pfSense), box, borne Wi-Fi, hub, téléphones IP.
- **Trames réelles** (octets) et **analyseur type Wireshark** : filtres d'affichage, détail champ par champ + hexdump, suivi de flux TCP, statistiques, export `.pcap`.
- **Réseau** : adressage IPv4/IPv6, ARP/NDP, DHCP/DHCPv6-SLAAC, DNS, HTTP/HTTPS, NAT/PAT, ACL, VLAN/trunk 802.1Q, routage inter-VLAN, STP/Rapid-PVST, EtherChannel (LACP/PAgP), routage statique/RIP/OSPF, VPN (GRE, IPsec ISAKMP/IKEv1 + ESP), SNMP (v1/v2c) + syslog, RADIUS/802.1X (EAP-MD5, PEAP, VLAN dynamique, MAB), VoIP (SIP/RTP) et QoS (LLQ).
- **Cybersécurité** : scan de ports, usurpation ARP (MITM), saturation de table MAC, serveur DHCP indésirable, port-security — avec TP dédiés en section « Cybersécurité ».
- **CCNA** : plan d'adressage VLSM, bonnes pratiques STP (PortFast/BPDU Guard) — section « CCNA ».
- **Habilitation Stormshield** : politique de filtrage (moindre privilège), diagnostic par le journal — section « Stormshield ».
- **TP d'exemple** (menu à listes déroulantes : section puis sujet) avec correction et vérification automatique du travail ; matrice de couverture du programme (menu Aide).
- Sauvegarde/chargement JSON, sauvegarde automatique dans le navigateur (localStorage).

## Fiches produits

✔ = valeurs relevées chez le constructeur (source indiquée dans la fiche) ; ≈ = valeurs typiques à vérifier auprès du constructeur exact.

## Limites connues (non simulé)

SNMPv3, IPv6 sur TCP/UDP applicatifs avancés, ACL IPv6, NAT-T/DPD/IKEv2, cryptographie réelle (chiffrements symboliques), CUCM/CME, VLAN hopping et SYN flood (abordés en cours), stacking/MSTP sur l'OmniSwitch.

## Développement

```
node tests/t_scen.js     # scénario de base bout en bout
node tests/t_sc.js       # tous les TP : build → vérif « avant » → solve → vérif « après »
node tests/t_an.js       # analyseur
node tests/t_cyber.js    # outils cybersécurité (nmap, arpspoof, macflood)
node tools/build.js      # reconstruit dist/simulateur-reseau.html (fichier autonome)
```

Lancer tous les tests : `for f in tests/t_*.js; do node "$f" || echo "FAIL $f"; done`
