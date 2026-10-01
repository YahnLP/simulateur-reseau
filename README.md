# Simulateur Réseau — Bac Pro CIEL / BTS SIO SISR

Créé par Yahn LE PRETTRE — Formaxion Landes · [Licence EUPL 1.2](LICENSE)

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

## Licence

**Simulateur Réseau** est distribué sous licence libre **EUPL 1.2** (European Union Public Licence, version 1.2) — texte officiel complet dans le fichier [`LICENSE`](LICENSE), également disponible sur le site de la Commission européenne : [interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12](https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12) (ex-« Joinup », l'ancienne adresse joinup.ec.europa.eu redirige automatiquement).

En résumé (ce résumé ne remplace pas le texte de la licence, seul juridiquement contraignant) :

- vous pouvez **utiliser**, **étudier**, **modifier** et **redistribuer** le logiciel, gratuitement, y compris dans un cadre professionnel ;
- si vous redistribuez le logiciel ou une version modifiée, le **code source doit rester accessible** aux personnes qui le reçoivent, conformément aux obligations de l'EUPL (article 5, clause de copyleft) ;
- les **droits d'auteur** sur le projet original restent détenus par Yahn LE PRETTRE / Formaxion Landes ;
- la publication sous EUPL **n'empêche pas** le titulaire des droits de proposer ultérieurement **d'autres éditions** du logiciel sous une licence différente, notamment une version commerciale — cette possibilité ne retire rien aux droits déjà accordés sur les versions publiées sous EUPL ;
- le nom « Simulateur Réseau », son logo et son identité visuelle restent la propriété de Yahn LE PRETTRE / Formaxion Landes ; leur usage n'est pas automatiquement accordé par la licence EUPL applicable au code source ;
- les **contributions externes** sont les bienvenues (voir [`CONTRIBUTING.md`](CONTRIBUTING.md)) ; une contribution significative pourra faire l'objet d'un accord complémentaire avant son intégration, notamment si elle doit pouvoir figurer dans une future édition propriétaire.

```
Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes
Licensed under the European Union Public Licence (EUPL), version 1.2.
```

## Développement

```
node tests/t_scen.js     # scénario de base bout en bout
node tests/t_sc.js       # tous les TP : build → vérif « avant » → solve → vérif « après »
node tests/t_an.js       # analyseur
node tests/t_cyber.js    # outils cybersécurité (nmap, arpspoof, macflood)
node tools/build.js      # reconstruit dist/simulateur-reseau.html (fichier autonome)
```

Lancer tous les tests : `for f in tests/t_*.js; do node "$f" || echo "FAIL $f"; done`
