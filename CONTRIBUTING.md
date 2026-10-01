# Contribuer à Simulateur Réseau

Merci de l'intérêt porté à ce projet. Les contributions — rapports de bugs, suggestions pédagogiques, nouveaux TP, corrections, améliorations du moteur — sont les bienvenues.

## Avant de proposer une contribution

- **Licence** : ce dépôt est distribué sous licence [EUPL 1.2](LICENSE). Toute contribution que vous proposez (via une *pull request*, un correctif, ou tout autre moyen) est soumise aux mêmes termes : en la proposant, vous acceptez qu'elle soit distribuée sous cette licence au même titre que le reste du projet.
- **Vos droits sur le code proposé** : ne soumettez que du code, des textes ou des ressources dont vous détenez les droits (code que vous avez écrit vous-même, ou que vous êtes autorisé à redistribuer sous les termes de l'EUPL). N'incluez pas de code copié depuis une source dont la licence est incompatible ou inconnue.
- **Contributions importantes** : pour une contribution significative (nouvelle fonctionnalité majeure, nouveau module, gros volume de code), le mainteneur du projet (Yahn LE PRETTRE / Formaxion Landes) pourra, avant de l'intégrer, vous demander un accord complémentaire. Cet accord permettrait notamment que votre contribution puisse aussi être intégrée dans d'autres éditions du logiciel (y compris une édition propriétaire ou commerciale distincte de la version EUPL), ce que l'EUPL seule ne garantit pas automatiquement au mainteneur sur le travail d'un tiers. Sans cet accord, votre contribution reste bien sûr utilisable dans le projet sous EUPL — cet accord ne concerne que la possibilité de la réutiliser *ailleurs*.
- Il n'existe pas aujourd'hui de CLA (*Contributor License Agreement*) formel pour ce projet ; un tel document pourra être mis en place ultérieurement si le volume de contributions le justifie.

## Comment contribuer

1. Ouvrez une *issue* pour discuter du changement envisagé avant d'investir du temps dans un développement important (cela évite les divergences de vue sur l'approche).
2. Respectez les conventions déjà en place dans le code (voir le document d'architecture du projet : organisation des fichiers `js/*.js`, conventions de nommage des ports d'équipement, structure d'un TP dans `scenarios.js`…).
3. Si vous modifiez un fichier `js/*.js`, pensez à relancer la suite de tests (`for f in tests/t_*.js; do node "$f" || echo "FAIL $f"; done`) et à reconstruire le fichier autonome (`node tools/build.js`) avant de proposer votre changement.
4. Décrivez clairement, dans votre *pull request*, ce que le changement apporte et comment le tester.

## Signaler un problème

Les *issues* GitHub sont le canal le plus simple : décrivez le comportement observé, le comportement attendu, et si possible les étapes pour reproduire le problème (idéalement avec un fichier `.json` de topologie).
