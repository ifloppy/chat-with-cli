# Self-host a private Relay with ChatGPT

A public Chat With CLI instance can be used as a bootstrap path: after a user
connects a workstation, an authorized ChatGPT session can use that workstation
to help deploy a separate private Relay on infrastructure the user controls.
This is the recommended exit path for sensitive or long-term use.

## Trust boundary

Do not give the public Relay, ChatGPT, or a chat transcript the new private
Relay's owner password or one-time setup token. The existing public Relay can
observe the MCP traffic it brokers, so credentials typed through its Agent are
not private from that operator.

Use ChatGPT for the non-secret deployment work:

1. Connect to the target VPS through an already-authorized shell or SSH setup.
2. Select a pinned Chat With CLI release rather than an unpinned development
   build. Download the binary and the same release's `SHA256SUMS`, then verify
   the checksum before installation.
3. Create a dedicated unprivileged `chat-with-cli` service account and a 0700
   state directory.
4. Install a reviewed systemd unit and configure Caddy/Nginx for HTTPS and
   WebSocket forwarding.
5. Run `chat-with-cli relay setup --instance-mode private` on the VPS. Leave the
   generated setup token on the VPS in its protected 0600 file.
6. Stop automation and have the human obtain the setup token through a trusted
   path and complete `https://<private-relay>/setup` directly in a browser.
7. After setup succeeds, ChatGPT may resume non-secret verification such as
   `chat-with-cli doctor`, `/health`, OAuth discovery, and service status.
8. Pair the workstation to the new private Relay and revoke the old public
   Relay device/token families from `/account` when migration is complete.

## Suggested request

Tell ChatGPT the target host and non-secret deployment preferences, for example:

> Deploy a private Chat With CLI Relay on my VPS using a pinned verified
> release, a dedicated unprivileged service account, systemd, and Caddy. Do not
> read, request, paste, or transmit my owner password or setup token. Stop when
> `/setup` is ready for me, then continue verification after I complete it.

The human-controlled `/setup` handoff is intentional. A public Relay is useful
for bootstrap automation, but it should not become the channel through which
the secrets for its replacement are created or transmitted.
