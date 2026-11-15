# Repository Template

This is a repository template for Cloudflare Workers projects.
# login-client-worker

Deployment configuration refreshed.

Worker de connexion par pseudo pour un compte Cloudflare individuel.

Configurer dans le Secret Store Cloudflare du compte cible un binding nommé
`MAIN_PASSWORD`. Sa valeur est le mot de passe du pseudo de ce compte.

Après validation, le Worker crée un jeton aléatoire à usage unique, valable
60 secondes et lié à l'adresse IP fournie. Une IP est bannie 10 minutes après
10 échecs et ne peut pas valider plus de cinq pseudos différents sur 30 minutes.
