# CIAM Home Lab — Optimizely & Entra External ID

Projet personnel de portail client fictif « Valora Asset Management », basé sur le modèle Alloy d’Optimizely CMS.

## Stack et fonctionnalités

- .NET 10, ASP.NET Core MVC et vues Razor.
- Optimizely CMS 13.5.1 : pages, blocs éditoriaux et médias.
- Microsoft Entra External ID : connexion native email/mot de passe, MFA par email et réinitialisation du mot de passe.
- Cookie client distinct de l’authentification des administrateurs CMS.

## Récupérer le projet sur un autre ordinateur

Si les règles de votre entreprise autorisent GitHub et ce projet personnel :

```powershell
git clone https://github.com/chanvines/ciam-optimizely-entra-external-id.git
cd ciam-optimizely-entra-external-id
```

Sans Git, utiliser sur GitHub **Code > Download ZIP**, puis extraire le fichier.

## Prérequis

- SDK .NET 10.
- SQL Server LocalDB sous Windows, ou un serveur SQL Server accessible.
- Un tenant et une application Microsoft Entra External ID configurés pour les flux utilisés.
- Les conditions de licence Optimizely applicables à votre environnement.

## Configuration et démarrage

Les fichiers de base de données, médias locaux, journaux, fichiers compilés et sauvegardes ne sont pas publiés. Le contenu CMS de l’ordinateur d’origine n’est donc pas transféré. Un nouvel environnement nécessite une base et une initialisation du contenu CMS.

Dans PowerShell, définir les valeurs adaptées à votre environnement avant de démarrer :

```powershell
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:EntraExternal__TenantSubdomain = 'votre-sous-domaine'
$env:EntraExternal__TenantId = 'votre-tenant-id'
$env:EntraExternal__ClientId = 'votre-client-id'
$env:ConnectionStrings__EPiServerDB = 'Server=(localdb)\MSSQLLocalDB;Database=CiamOptimizelyPortal;Integrated Security=True;TrustServerCertificate=True'
dotnet restore src/CiamOptimizelyPortal.csproj
dotnet run --project src/CiamOptimizelyPortal.csproj
```

Le profil de lancement utilise `https://localhost:5000`. Configurer un certificat HTTPS de développement approuvé selon les règles du poste.

Ne pas enregistrer de mot de passe dans les fichiers suivis par Git. Utiliser des variables d’environnement ou un gestionnaire de secrets.

## État actuel : prototype

- Les services de connexion, MFA et réinitialisation sont enregistrés comme clients HTTP dans Startup.cs.
- La session MFA et réinitialisation expire après une minute sans requête. Le cookie client connecté conserve sa durée de 30 minutes. La validité des codes reste contrôlée par Entra.
- L’inscription et l’enrôlement MFA ne sont pas implémentés.
- La page compte est une démonstration, sans données de portefeuille réelles.
- La recherche CMS est désactivée. Vérifications du parcours SSPR : dotnet run --project tests/PasswordResetChecks/PasswordResetChecks.csproj

## Organisation

- `src/Controllers` : routes CMS et parcours client.
- `src/Services` : appels Entra et validation des tokens.
- `src/Models`, `src/Views`, `src/Business` : contenu et rendu CMS.
- `src/wwwroot`, `src/Assets` : ressources et styles.
- `postman/` : configuration Postman initiale.

La configuration personnelle peut être placée dans src/appsettings.Local.json, exclu de Git et chargé automatiquement. Les variables d’environnement et les arguments de ligne de commande ont priorité sur ce fichier. Les identifiants Entra publiés sont des valeurs fictives.

La fin de réinitialisation est vérifiée automatiquement en respectant poll_interval, avec une attente maximale de confirmation de 60 secondes. Un délai dépassé ne prouve pas un échec du changement de mot de passe : le client peut essayer de se connecter. Les journaux indiquent uniquement le statut normalisé, le statut HTTP et la présence éventuelle d’une erreur.
