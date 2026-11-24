# n8n-nodes-pushover-with-encryption

An n8n community node that sends [Pushover](https://pushover.net/) notifications
**with optional end-to-end encryption** per Pushover's
[end-to-end encryption specification](https://pushover.net/api#e2ee)
(gzip → AES-256-CBC → HMAC-SHA256).

A drop-in alternative to the built-in **Pushover** node, with one extra control:
**Encrypt Fields**.

- ✅ Same operations and parameters as the built-in Pushover node
- ✅ Encrypts `message`, `title`, `url` and `url_title`, the four fields
  Pushover's end-to-end encryption covers
- ✅ Encryption is on by default (opt-out, not opt-in), and fails closed: the
  node refuses to send rather than fall back to plaintext (see
  [Security](#security))
- ✅ No runtime dependencies: Node.js `crypto` plus the standard Compression
  Streams API, within n8n's community-node rules (including the n8n Cloud ones)
- ✅ Sets `encrypted=1` automatically when at least one field is encrypted
- ✅ Interoperable with Pushover's reference OpenSSL implementation, both ways

## Compatibility

- **n8n 1.85.0 or newer**, including n8n 2.x and n8n 3. The node is
  type-checked and tested against both the n8n 2.x and the n8n 3.x workflow
  libraries in CI.
- **n8n 3:** this package is not a verified community node. n8n 3.0 changes
  the default of `N8N_UNVERIFIED_PACKAGES_ENABLED` to `false`, which stops
  unverified community packages from loading. Set
  `N8N_UNVERIFIED_PACKAGES_ENABLED=true` on n8n 3 instances that use this node.

## Install

In your n8n instance:

1. Make sure community packages are enabled (`N8N_COMMUNITY_PACKAGES_ENABLED`,
   on by default) and, on n8n 3, see [Compatibility](#compatibility).
2. Open **Settings → Community Nodes → Install**.
3. Enter `@geoffreyr/n8n-nodes-pushover-with-encryption` and confirm.

Or install manually via npm into your n8n custom-nodes directory:

```bash
cd ~/.n8n/nodes
npm install @geoffreyr/n8n-nodes-pushover-with-encryption
```

Restart n8n. The node will appear as **Pushover (with Encryption)** in the
node picker.

## Configure the credential

Create a credential of type **Pushover (with Encryption) API**:

| Field                    | Required | What it is                                                                                                            |
| ------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------- |
| **Application Token**    | yes      | Your Pushover application token (`APP_TOKEN`), created from the Pushover dashboard.                                   |
| **Encryption Key (Hex)** | optional | A 64-character hexadecimal key (256 bits) used for end-to-end encryption. Must match the key configured in your apps. |

Only this node can use the credential: n8n refuses it to every other node,
including the **HTTP Request** node. This keeps anyone who may _use_ a shared
credential from sending the token to a server of their choice. n8n versions
that predate this restriction ignore it.

### Generating an encryption key

```bash
# 32 random bytes, hex-encoded → 64 hex chars
openssl rand -hex 32
```

Configure the same hex key in the Pushover apps that should decrypt your
messages (Pushover's [iOS and Android apps](https://pushover.net/api#e2ee)
support end-to-end encryption). Pushover's servers never see the key; they
only relay the opaque ciphertext.

## Encryption details

Each selected field is encrypted independently per
[Pushover's spec](https://pushover.net/api#e2ee):

1. UTF-8 encode the plaintext
2. GZIP-compress (a standard RFC 1952 gzip stream)
3. Generate a random 16-byte IV
4. AES-256-CBC encrypt (PKCS7 padding) the compressed bytes
5. Compute HMAC-SHA256 over `IV ‖ ciphertext` with the same key
6. Concatenate `IV ‖ ciphertext ‖ HMAC` and base64-encode

When at least one field is encrypted, the node sets `encrypted=1` on the
multipart POST so Pushover knows to forward the opaque payload to your devices.

With `encrypted=1`, Pushover's spec treats `message`, `title`, `url` and
`url_title` as encrypted. Two consequences:

- **Keep all four fields selected under Encrypt Fields.** A field sent in
  plaintext next to encrypted ones may not display correctly on the device.
  To send an unencrypted message, deselect all four.
- **An encrypted message always has a title.** Without one, Pushover fills in
  the application name in plaintext, which the apps then try, and fail, to
  decrypt. The node sends an encrypted `n8n` title instead. Set **Title** to
  choose your own.

### Worked example (shell)

```sh
#!/bin/sh
KEY="your-64-char-hex-key-here"

encrypt() {
  IV=$(openssl rand -hex 16)
  CT=$(echo -n "$1" | gzip -9 | \
    openssl enc -aes-256-cbc -K "$KEY" -iv "$IV" | xxd -p | tr -d '\n')
  HMAC=$(echo -n "${IV}${CT}" | xxd -r -p | \
    openssl dgst -sha256 -mac HMAC -macopt hexkey:"$KEY" | awk '{print $NF}')
  echo -n "${IV}${CT}${HMAC}" | xxd -r -p | openssl base64 -A
}

curl -s https://api.pushover.net/1/messages.json \
  -F "token=APP_TOKEN" \
  -F "user=USER_KEY" \
  -F "title=$(encrypt "hellorld")" \
  -F "message=$(encrypt "This has been encrypted")" \
  -F "encrypted=1"
```

This is Pushover's own example. The node and the snippet are interoperable:
each decrypts the other's output. The test suite includes known-answer vectors
produced by exactly this pipeline (`gzip -9` and OpenSSL), and the node's own
ciphertext decrypts with `openssl enc -d` and `gunzip`. The bytes are not
identical even with the same IV, because the node compresses with zlib's
default level.

## Usage

1. Add a **Pushover (with Encryption)** node to your workflow.
2. Pick the **Pushover (with Encryption) API** credential.
3. Fill in **User or Group Key**, **Message**, and optional fields.
4. Leave all four **Encrypt Fields** selected (the default), or deselect all
   of them to send the message unencrypted.
5. Run.

The node's subtitle on the canvas shows whether it sends encrypted messages.

## Limitations

- **Only four fields are encrypted.** Pushover's spec covers `message`,
  `title`, `url` and `url_title`. The user key, device, priority, sound,
  timestamp, TTL, HTML flag and attachments travel in plaintext (over HTTPS)
  and are visible to Pushover.
- **Length limits.** Pushover documents its limits for the text you write:
  1024 characters for the message, 250 for the title, 512 for the URL and 100
  for the URL title. It does not say how it applies them to encrypted values,
  which are always longer (even a 1-character URL title is 108 characters once
  encrypted). Keep the plaintext within the limits.
- **No key rotation built in.** If you rotate the device-side key, you must
  update the credential at the same time. There's no per-message key id.

## Security

What the encryption protects, and what it does not:

- **Protected:** the content of the four encrypted fields, from Pushover and
  from Apple's and Google's push services.
- **Not protected:** everything else Pushover needs or receives (see
  [Limitations](#limitations)), plus the size and timing of each message.
- **Properties of Pushover's scheme,** which the node cannot change without
  breaking compatibility with the apps:
  - The same key is used for AES and for HMAC. This departs from the usual
    practice of separate keys, though no practical attack on this
    encrypt-then-MAC construction is known.
  - The plaintext is compressed before it is encrypted, so the length of the
    ciphertext depends on the content. Avoid putting a secret and text an
    attacker controls in the same field, where the size of messages could
    reveal the secret, as in the CRIME and BREACH attacks.
  - Each field is authenticated on its own, not as part of a message.
    Whoever relays messages could swap encrypted fields between messages, or
    replay an old one, without the apps noticing.

How the node handles failures:

- **It fails closed.** An item fails, and nothing is sent, if **Encrypt
  Fields** asks for encryption and the credential has no key or an invalid
  one, or if **Encrypt Fields** (for example from an expression, or from an AI
  agent when the node runs as a tool) contains anything other than
  `message`, `title`, `url` or `url_title`. Values that are not text, such as
  a number from an expression, are encrypted like any other text.
- **The application token stays out of URLs.** Messages are sent as a
  multipart POST with the token in the body. The read-only endpoints (the
  sound list and the credential test) take it in the query string, as
  Pushover's API requires.
- **It stops early on account-wide refusals.** With **Continue On Fail**
  set, once Pushover rejects the token or reports the monthly quota used up,
  the remaining items are marked as not sent instead of being sent anyway.
  Pushover temporarily blocks IP addresses that keep sending failing
  requests.
- **As an AI agent tool,** do not let the model choose **Encrypt Fields**:
  an empty selection legitimately sends a plaintext message.

## Development

Use Node.js 24 or newer (n8n's own minimum), or Node.js 22.16+ with npm 11
(`npm install --global npm@11`): the lockfile is written by npm 11, and the
npm 10 that ships with Node.js 22 can reject it in `npm ci`. The tooling is
n8n's official [`@n8n/node-cli`](https://www.npmjs.com/package/@n8n/node-cli)
(`n8n-node`); `npm run dev` runs n8n in a container, so it needs Docker or
Podman.

```bash
git clone https://github.com/geofox/n8n-nodes-pushover-with-encryption.git
cd n8n-nodes-pushover-with-encryption
npm ci
npm run build       # n8n-node build: compile and copy the icon into dist/
npm run lint        # n8n-node lint: n8n's community-node rules, strict mode (ESLint 10)
npm run typecheck   # TypeScript check of sources and tests
npm test            # Jest: encryption helper and node behaviour
npm run dev         # n8n-node dev: n8n in Docker/Podman with this node loaded
```

`npm run lint` runs in strict mode (`"strict": true` in `package.json`), so
`eslint.config.mjs` must stay identical to the default that `n8n-node`
generates.

## Releasing

Releases are published from GitHub Actions with an npm provenance attestation,
which n8n requires for community nodes:

1. On an up-to-date `main`, run `npm run release`. It lints, builds, bumps the
   version, updates `CHANGELOG.md`, commits, tags `vX.Y.Z` and pushes.
2. The tag push runs [`publish.yml`](.github/workflows/publish.yml), which
   tests and publishes the package with provenance. If a tag was created
   another way (for example from the GitHub Releases page) and the workflow
   did not start, run **Publish** manually from the Actions tab on that tag.

One-time setup: configure npm Trusted Publishing for this repository and
`publish.yml` (or add an `NPM_TOKEN` repository secret). The workflow file
describes both options.

## License

[MIT](./LICENSE).

This package is an **independent** community node — it was written against
the published [Pushover API](https://pushover.net/api) and the MIT-licensed
[`n8n-nodes-starter`](https://github.com/n8n-io/n8n-nodes-starter) template
only. It does not embed any code from the n8n core repository, which is
distributed under the Sustainable Use License.

`Pushover` and the Pushover wordmark are trademarks of Superblock LLC, used
here nominatively to identify the service this node talks to.
