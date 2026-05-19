# n8n-nodes-pushover-with-encryption

An n8n community node that sends [Pushover](https://pushover.net/) notifications
**with optional client-side field encryption** per Pushover's
[encrypted-message specification](https://pushover.net/api#encrypted)
(gzip → AES-256-CBC → HMAC-SHA256).

A drop-in alternative to the built-in **Pushover** node, with one extra control:
**Encrypt Fields**.

- ✅ Same operations and parameters as the built-in Pushover node
- ✅ Per-field encryption toggle for `title`, `message`, `url`, `url_title`
- ✅ All four toggles default to ON — encryption is opt-out, not opt-in
- ✅ Pure Node.js `crypto` + `zlib` — no native deps
- ✅ Sets `encrypted=1` automatically when at least one field is encrypted
- ✅ Constant-time HMAC verification on the round-trip helper

## Install

In your n8n instance:

1. Set `N8N_COMMUNITY_PACKAGES_ENABLED=true` in the environment of your n8n
   container (already required for any community node).
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

| Field              | Required | What it is                                                                                                              |
| ------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| **API Token**      | yes      | Your Pushover application token (`APP_TOKEN`), created from the Pushover dashboard.                                     |
| **Encryption Key** | optional | A 64-character hexadecimal key (256 bits) used for client-side encryption. Must match the key configured in your apps. |

### Generating an encryption key

```bash
# 32 random bytes, hex-encoded → 64 hex chars
openssl rand -hex 32
```

You configure the same hex key in your Pushover apps (iOS / Android / Desktop)
under the encryption setting. Pushover's server never sees the key — it only
relays the opaque ciphertext.

## Encryption details

Each selected field is encrypted independently per Pushover's spec:

1. UTF-8 encode the plaintext
2. GZIP-compress (level 9)
3. Generate a random 16-byte IV
4. AES-256-CBC encrypt (PKCS7 padding) the compressed bytes
5. Compute HMAC-SHA256 over `IV ‖ ciphertext` with the same key
6. Concatenate `IV ‖ ciphertext ‖ HMAC` and base64-encode

When at least one field is encrypted, the node sets `encrypted=1` on the
multipart POST so Pushover knows to forward the opaque payload to your devices.

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

This community node produces byte-identical output to the shell snippet above,
modulo the random IV.

## Usage

1. Add a **Pushover (with Encryption)** node to your workflow.
2. Pick the **Pushover (with Encryption) API** credential.
3. Fill in **User Key**, **Message**, and optional fields.
4. Under **Encrypt Fields**, deselect anything you want sent in plaintext.
   All four are pre-selected.
5. Run.

If you want lockscreen previews of the title but encrypt the body, deselect
**Title** from **Encrypt Fields**.

## Limitations

- **Attachments are not encrypted.** Pushover's spec covers form fields only;
  binary attachments travel as-is.
- **Server-side validation runs on the ciphertext.** Length limits still apply
  to the encrypted form-field values, not to the plaintext.
- **No key rotation built in.** If you rotate the device-side key, you must
  update the credential at the same time. There's no per-message key id.

## Development

```bash
git clone https://github.com/geofox/n8n-nodes-pushover-with-encryption.git
cd n8n-nodes-pushover-with-encryption
npm install
npm run build       # tsc + gulp icons
npm run lint        # eslint with n8n community ruleset
npm test            # jest on the encryption helper
```

## License

[MIT](./LICENSE).

This package is an **independent** community node — it was written against
the published [Pushover API](https://pushover.net/api) and the MIT-licensed
[`n8n-nodes-starter`](https://github.com/n8n-io/n8n-nodes-starter) template
only. It does not embed any code from the n8n core repository, which is
distributed under the Sustainable Use License.

`Pushover` and the Pushover wordmark are trademarks of Superblock LLC, used
here nominatively to identify the service this node talks to.
