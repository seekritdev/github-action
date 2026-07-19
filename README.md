# seekrit GitHub Action

Load secrets from [seekrit](https://seekrit.dev) into your GitHub Actions job — resolved,
decrypted **on the runner**, masked in the logs, and injected into `$GITHUB_ENV` so every
subsequent step just sees them as environment variables.

seekrit is end-to-end encrypted: this action decrypts your secrets locally using the private key
carried by your service token. **The seekrit API never sees plaintext.**

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: seekritdev/github-action@v1
        with:
          token: ${{ secrets.SEEKRIT_TOKEN }}

      # Later steps see the secrets as environment variables:
      - run: ./deploy.sh # e.g. $DATABASE_URL, $API_KEY, … are set
```

Store your service token as an [encrypted Actions
secret](https://docs.github.com/actions/security-guides/encrypted-secrets) named `SEEKRIT_TOKEN`.
A [service token](https://seekrit.dev/docs/guides/service-tokens) is bound to a single application
environment, so there is nothing else to configure — it resolves its own org, app, environment, and
composed groups.

## Inputs

| Input         | Default                    | Description                                                                                          |
| ------------- | -------------------------- | ---------------------------------------------------------------------------------------------------- |
| `token`       | _(required)_               | seekrit service token (`skt_…`). Pass `${{ secrets.SEEKRIT_TOKEN }}`.                                 |
| `api-url`     | `https://api.seekrit.dev`  | seekrit API base URL.                                                                                 |
| `with`        | `""`                       | Group→environment overrides, one `group:env` per line (or comma-separated). Mirrors the CLI `--with`. |
| `export-env`  | `true`                     | Inject each secret into `$GITHUB_ENV` for subsequent steps.                                           |
| `set-outputs` | `false`                    | Also expose each secret as a step output (`steps.<id>.outputs.<NAME>`).                               |
| `mask`        | `true`                     | Register every value with the runner (`::add-mask::`) so it is redacted from logs.                    |
| `prefix`      | `""`                       | String prepended to every injected variable name.                                                    |
| `include`     | `""`                       | If set, inject only these names (comma/newline separated).                                            |
| `exclude`     | `""`                       | Names to skip (comma/newline separated).                                                              |

## Outputs

| Output          | Description                  |
| --------------- | ---------------------------- |
| `secrets-count` | Number of secrets injected.  |

## Examples

### Consume secrets in later steps

```yaml
steps:
  - uses: seekritdev/github-action@v1
    with:
      token: ${{ secrets.SEEKRIT_TOKEN }}
  - run: |
      echo "connecting to the database..."   # $DATABASE_URL is set & masked
      ./migrate.sh
```

### Namespace with a prefix, and filter

```yaml
- uses: seekritdev/github-action@v1
  with:
    token: ${{ secrets.SEEKRIT_TOKEN }}
    prefix: "SEEKRIT_"          # -> $SEEKRIT_DATABASE_URL, ...
    include: DATABASE_URL, API_KEY
```

### Compose a group at a specific environment

```yaml
- uses: seekritdev/github-action@v1
  with:
    token: ${{ secrets.SEEKRIT_TOKEN }}
    with: |
      platform:staging
      payments:staging
```

### Read as step outputs instead of env

```yaml
- id: seekrit
  uses: seekritdev/github-action@v1
  with:
    token: ${{ secrets.SEEKRIT_TOKEN }}
    export-env: "false"
    set-outputs: "true"
- run: echo "count=${{ steps.seekrit.outputs.secrets-count }}"
  # individual values: ${{ steps.seekrit.outputs.DATABASE_URL }}
```

> Prefer masked environment variables (`export-env`) over step outputs where you can — outputs are
> stored in the workflow run and are a slightly larger surface than env masking.

## How it works

1. The action reads your `skt_…` service token (which _is_ the private key — it is never sent).
2. It calls `GET /v1/resolve`, receiving **ciphertext only**: the ordered secret layers (composed
   groups → application environment) plus a per-layer data key wrapped to the token's public key.
3. It unwraps each data key and decrypts every secret locally (ECDH P-256 → HKDF-SHA256 →
   AES-256-GCM), applying the same precedence as `seekrit run` — the app environment wins over
   composed groups.
4. Each value is masked (`::add-mask::`) and written to `$GITHUB_ENV` / step outputs.

Precedence, formats, and the zero-knowledge model are documented at
<https://seekrit.dev/docs>.

## Security

- **Zero-knowledge.** Decryption happens on the runner. The API only ever holds ciphertext and
  public keys — never plaintext, private keys, or passphrases.
- **Masked by default.** Every injected value is registered with the runner so it is redacted from
  logs (multi-line values are masked line by line). Leave `mask` on.
- **No third-party runtime dependencies.** The published `dist/` bundle contains only this repo's
  own code — no `node_modules` are pulled at action runtime — so the code handling your secrets is
  small and auditable.
- **Scope your token.** Grant each token only the environment it needs, and rotate/revoke from the
  seekrit dashboard. A leaked CI token is contained to a single environment.
- Treat injected environment variables like any other CI secret: they are available to every step
  in the job, including third-party actions you invoke afterward.

## Versioning

Reference a major version so you get non-breaking updates:

```yaml
- uses: seekritdev/github-action@v1
```

Pin to an exact release (e.g. `@v1.0.0`) or a commit SHA if you require immutability.

## Development

```bash
npm ci
npm run typecheck
npm test          # decrypts golden vectors from @seekrit/crypto (crypto is byte-compatible)
npm run build     # bundles src/ -> dist/index.js (esbuild); commit the result
npm run lint
```

The bundled `dist/index.js` is committed and must stay in sync with `src/` — CI fails if it drifts.
The crypto is a vendored, decrypt-only port of the canonical `@seekrit/crypto`; the golden-vector
test (`test/fixtures/vectors.json`) is generated by the real implementation and pins byte-for-byte
compatibility.

## License

[MIT](./LICENSE)
