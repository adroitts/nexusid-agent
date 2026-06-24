# Signing & distribution — NexusID Sync Agent

Windows binaries are Authenticode-signed with **Azure Trusted Signing** (account `nexus-signer`),
then published to GitHub Releases and consumable via **irm**, **Chocolatey**, and **Winget** for
**x64 and x86**. Linux/macOS ship as signed-by-checksum tarballs.

> **Where signing actually runs (current):** the release is **GitHub Actions**
> (`.github/workflows/release.yml`), triggered by a `v*` tag — *not* the Azure DevOps pipeline the
> sections below describe. Its two `azure/trusted-signing-action@v0` steps sign the `.exe` and `.msi`
> with **`nexus-signer` / `Signer`** (East US, `https://eus.codesigning.azure.net/`), authenticated by
> the **`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_CREDENTIALS`** repo
> secrets — the **NexusID-tenant** SP (app `475384de`, tenant `166d7ecb-…`) that holds the *Artifact
> Signing Certificate Profile Signer* role on `nexus-signer`. macOS uses the `APPLE_*` / `AC_*` secrets.
> The Azure DevOps sections (§2, `azure-pipelines-agent.yml`, service connections) are **historical**.
> Cybrium remains a documented fallback, but its SP is in a different tenant.

Azure Trusted Signing issues short-lived certs from the service (there is no cert file you hold).

---

## 1. The signer (already provisioned — Cybrium)

Signing uses the **Cybrium** Trusted Signing account (part of adroitts), which is provisioned and
working:

| | |
| --- | --- |
| Subscription | **CybriumAI** `26ec4dc5-a309-45e1-9620-01238fceb760` (tenant `9f1735b5-…`, MFA required) |
| Account | `cybrium-signing` (RG `cybrium-signing-rg`, **centralus**) |
| Certificate profile | `cybrium` — **PublicTrust, Succeeded** |
| Endpoint | `https://cus.codesigning.azure.net/` (central US) |
| Identity validation | `8607c9cc-1dd4-470b-bde9-9a52341832c6` (Completed) |

> The earlier `nexus-signer` account (sub NexusID) could not provision a PublicTrust profile —
> every attempt failed with an opaque backend `UnknownError`. Cybrium is used instead.

**Grant the CI identity the signer role.** The Azure DevOps service connection's service principal
needs **Trusted Signing Certificate Profile Signer** on the account:

```bash
az account set --subscription 26ec4dc5-a309-45e1-9620-01238fceb760
ACCOUNT_ID=$(az trustedsigning show -n cybrium-signing -g cybrium-signing-rg --query id -o tsv)
az role assignment create \
  --assignee <SERVICE_CONNECTION_SP_APP_OR_OBJECT_ID> \
  --role "Trusted Signing Certificate Profile Signer" \
  --scope "$ACCOUNT_ID"
```

---

## 2. Azure DevOps wiring

1. Install the **Trusted Signing** extension for Azure DevOps (Marketplace → "Trusted Signing").
2. Create an **AzureRM service connection** named `cybrium-trusted-signing` scoped to subscription
   **CybriumAI** `26ec4dc5-…` (the SP granted the signer role in §1).
3. The pipeline variables are already set to the Cybrium signer in `azure-pipelines-agent.yml`;
   only flip the gate:
   - `signWindows = true`
   - `azureServiceConnection = cybrium-trusted-signing`
   - `trustedSigningAccountName = cybrium-signing`
   - `certificateProfileName = cybrium`
   - `trustedSigningEndpoint = https://cus.codesigning.azure.net/` (central US)

The `TrustedSigning@0` step in the pipeline signs `nexus-agent.exe` (x64 and x86) before zipping;
with `signWindows=false` the pipeline still builds unsigned, so nothing blocks until §1 is done.

> **Alternative (no marketplace task):** `signtool sign /v /debug /dlib Azure.CodeSigning.Dlib.dll
> /dmdf metadata.json nexus-agent.exe`, authenticated by an `AzureCLI@2` step using the same service
> connection. `metadata.json` carries `{Endpoint, CodeSigningAccountName, CertificateProfileName}`.

## 3. Endpoint regions

`trustedSigningEndpoint` must match the account's region: East US `https://eus.codesigning.azure.net/`,
West US 2 `https://wus2.codesigning.azure.net/`, West Central US `https://wcus...`, North Europe
`https://neu...`, West Europe `https://weu...`.

---

## 4. Distribution channels (produced by the release)

| Channel | Command |
| --- | --- |
| **irm** (Windows, x64/x86) | `irm https://raw.githubusercontent.com/adroitts/nexusid-agent/main/packaging/install.ps1 \| iex` |
| **curl** (Linux/macOS) | `curl -fsSL https://raw.githubusercontent.com/adroitts/nexusid-agent/main/packaging/install.sh \| sh` |
| **Chocolatey** | `choco install nexus-agent` |
| **Winget** | `winget install NexusID.Agent` |

The pipeline fills the version + SHA-256 into the Chocolatey (`nexus-agent.nuspec` + tools) and
Winget (`NexusID.Agent.*.yaml`) manifests and attaches them to each release as
`nexus-agent-choco-<tag>.zip` / `nexus-agent-winget-<tag>.zip`.

**Publishing to the public repos (one-time per release, manual):**
- **Chocolatey:** `choco pack` the filled `chocolatey/` dir, then `choco push nexus-agent.<ver>.nupkg --source https://push.chocolatey.org/` with your API key.
- **Winget:** open a PR to `microsoft/winget-pkgs` under `manifests/n/NexusID/Agent/<ver>/` with the filled yaml (or use `wingetcreate submit`).

The `irm`/`curl` installers and the GitHub release require **no** repo submission — they work the
moment the release is published.

## 5. Cut a release

`git tag agent-v0.1.0 && git push origin agent-v0.1.0` → the pipeline builds all targets, signs the
Windows binaries (if `signWindows=true`), and publishes the GitHub release with binaries + checksums
+ choco/winget manifests + install scripts.
