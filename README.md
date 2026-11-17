# Repository Template

This is a repository template for Cloudflare Workers projects.
# login-client-worker

Deployment configuration refreshed.

Worker de connexion par pseudo pour un compte Cloudflare individuel.

Configurer dans le Secret Store Cloudflare du compte cible deux bindings nommés
`MAIN_USERNAME` et `MAIN_PASSWORD`.

- `MAIN_USERNAME` : le pseudo autorisé pour se connecter.
- `MAIN_PASSWORD` : le mot de passe associé à ce pseudo.

Ces deux secrets doivent être déclarés dans `wrangler.toml` (section `[[secret_store_secrets]]`) et leurs valeurs doivent être renseignées dans le Secret Store Cloudflare du compte cible (via le dashboard Cloudflare ou `wrangler secret put`).

Après validation, le Worker crée un jeton aléatoire à usage unique, valable
60 secondes et lié à l'adresse IP fournie. Une IP est bannie 10 minutes après
10 échecs et ne peut pas valider plus de cinq pseudos différents sur 30 minutes.
