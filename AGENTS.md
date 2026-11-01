# Consignes du projet

- Échanger avec l’utilisateur en français. Toute l’interface du portail doit être en anglais.
- Construire des parcours clients réels : pas de boutons de diagnostic dans l’interface. La vérification de fin de SSPR est automatique.
- Référence visuelle : bleu marine, accents or, marque Valora. Conserver trois accès distincts : Client Login (Entra External ID), Internal Users (futur SSO Entra workforce), administration Optimizely séparée.

- Après chaque modification de code autorisée, vérifier les changements, effectuer les contrôles adaptés, puis committer et pousser vers le dépôt GitHub configuré, sauf instruction contraire de l’utilisateur.
- Avant chaque commit et chaque envoi, vérifier les fichiers suivis et le diff pour exclure mots de passe, clés, tokens, identifiants et sous-domaines des tenants, identifiants d’applications et autres informations personnelles ou sensibles.
- Utiliser des valeurs fictives dans les fichiers publiés. Conserver la configuration personnelle dans `src/appsettings.Local.json` (ignoré par Git) ou dans des variables d’environnement.
- Ne jamais publier les sauvegardes, bases locales, journaux ou fichiers générés. Ne pas réécrire l’historique distant sans autorisation explicite.
