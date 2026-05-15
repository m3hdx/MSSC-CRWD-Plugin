# CrowdStrike Falcon Plugin for Microsoft Security Copilot

Read-only enrichment plugin that lets the **Alfred - SOC** agent query
CrowdStrike Falcon for detections, vulnerabilities, and Next-Gen SIEM
events directly from a Copilot prompt.

-----

## What this plugin does

Three SOC use cases, exposed as eight tightly-described skills:

|Use case                                          |Skills                                                                                                |
|--------------------------------------------------|------------------------------------------------------------------------------------------------------|
|**Artifact → detections** (user, device, IP, hash)|`SearchAlertsByFQL` → `GetAlertDetails`, plus `SearchDevices` → `GetDeviceDetails` for host resolution|
|**CVE → affected assets**                         |`SearchVulnerabilities` (filter by CVE) → `GetVulnerabilityDetails` (returns each affected host)      |
|**NGSIEM advanced search (CQL)**                  |`StartNGSIEMSearch` → poll `GetNGSIEMSearchResults`                                                   |

All operations are **read-only** and respect the deny-list in the
Alfred agent definition (no remediation, no RTR, no policy or config
changes, no user/token management).

-----

## What you’ll deploy

|File                             |What it is                                 |Where it goes                                    |
|---------------------------------|-------------------------------------------|-------------------------------------------------|
|`crowdstrike-alfred-plugin.yaml` |Security Copilot plugin manifest           |Uploaded into Security Copilot > Plugins > Custom|
|`crowdstrike-alfred-openapi.yaml`|OpenAPI 3.0.1 spec, curated to 8 operations|Hosted at a URL Security Copilot can reach       |

-----

## Prerequisites

1. **Security Copilot workspace** with admin rights to add custom plugins.
1. **Falcon API client** (Falcon console → Support and resources → API
   clients and keys → Create API client).
1. **Hosting** for the OpenAPI spec — a public URL is acceptable
   because it contains no secrets; most enterprises use either:
- a private GitHub repo + raw URL via a deploy token, or
- an Azure Storage Blob with anonymous read on a single file, or
- the company’s internal artifact server (must be reachable from
  `*.security.microsoft.com` — i.e. publicly addressable for the
  Copilot service).

-----

## Required CrowdStrike API scopes

When creating the Falcon API client, enable these scopes:

|UI scope                  |Falcon API scope name           |Used by                                           |
|--------------------------|--------------------------------|--------------------------------------------------|
|Alerts → **Read**         |`alerts:read`                   |`SearchAlertsByFQL`, `GetAlertDetails`            |
|Hosts → **Read**          |`devices:read`                  |`SearchDevices`, `GetDeviceDetails`               |
|Vulnerabilities → **Read**|`spotlight-vulnerabilities:read`|`SearchVulnerabilities`, `GetVulnerabilityDetails`|
|NGSIEM → **Read**         |`humio-auth-proxy:read`         |`GetNGSIEMSearchResults`                          |
|**NGSIEM → Write** ⚠️      |`humio-auth-proxy:write`        |`StartNGSIEMSearch`                               |


> ⚠️ **Important — NGSIEM scope mismatch in the supplied scopes sheet.**
> The scopes spreadsheet I worked from shows **NGSIEM: Read = Yes,
> Write = No**. Falcon classifies *submitting* a query job as a
> `:write` operation (it creates a server-side job resource), even
> though the analyst is only *reading* data. Without NGSIEM **Write**,
> use case #3 will return **403** on every search.
> 
> Either grant NGSIEM **Write** on the API client, or remove the
> `StartNGSIEMSearch` / `GetNGSIEMSearchResults` operations from the
> OpenAPI spec to fail fast at install time.

Also tick **NGSIEM Saved Queries: Read** and **NGSIEM Dashboards: Read**
if you plan to extend the plugin to list saved queries or dashboards
later.

-----

## Step-by-step deployment

### 1. Create the Falcon API client

- Falcon console → **Support and resources → API clients and keys → Create API client**
- Name: `MS Security Copilot - Alfred SOC (read)`
- Description: include the date, the Copilot workspace, and the contact owner
- Scopes: tick those listed in the table above
- **Save** and capture the **CLIENT ID**, **SECRET**, and **BASE URL**.
  The secret is shown **once** — store it in your secret vault before
  closing the dialog.

### 2. Choose your Falcon cloud

The Base URL shown when the API client is created tells you which cloud
your CID lives in:

|Cloud   |Base URL                                |
|--------|----------------------------------------|
|US-1    |`https://api.crowdstrike.com`           |
|US-2    |`https://api.us-2.crowdstrike.com`      |
|EU-1    |`https://api.eu-1.crowdstrike.com`      |
|US-GOV-1|`https://api.laggar.gcw.crowdstrike.com`|
|US-GOV-2|`https://api.us-gov-2.crowdstrike.mil`  |

If you are **not** on US-1, edit `crowdstrike-alfred-plugin.yaml`
before uploading and change the `Authorization.TokenEndpoint` line:

```yaml
TokenEndpoint: https://api.<your-cloud>.crowdstrike.com/oauth2/token
```

(The `EndpointUrlSettingName: FalconCloud` line at the bottom of the
manifest takes care of the per-call API base URL automatically.)

### 3. Host the OpenAPI spec

Upload `crowdstrike-alfred-openapi.yaml` somewhere Security Copilot
can fetch it over HTTPS. Examples:

- Private GitHub gist → use the *raw* URL.
- Azure Storage Blob → anonymous read on the blob only.
- Internal HTTPS server with a public DNS record (no auth needed; the
  spec contains no secrets).

Copy the final URL into `crowdstrike-alfred-plugin.yaml`:

```yaml
OpenApiSpecUrl: https://your-host/crowdstrike-alfred-openapi.yaml
```

### 4. Upload the plugin

- Security Copilot → top-right plugin icon → **Manage plugins**.
- Scroll to **Custom** and click **Add plugin**.
- Upload type: **Copilot for Security plugin** (not OpenAI plugin).
- Upload `crowdstrike-alfred-plugin.yaml`.
- Security Copilot will prompt for:
  - `Client ID` — paste the Falcon API client ID
  - `Client Secret` — paste the Falcon API client secret
  - `FalconCloud` — paste the Falcon base URL (e.g. `https://api.us-2.crowdstrike.com`)
  - `NGSIEMDefaultRepository` — e.g. `search-all`
- Click **Save**.

### 5. Bind the plugin to the Alfred - SOC agent

If you author the agent via YAML, add the plugin’s `Descriptor.Name`
to the agent’s `RequiredSkillsets`:

```yaml
AgentDefinitions:
  - Name: Alfred-SOC
    # ...existing fields...
    RequiredSkillsets:
      - CrowdStrike.Falcon.AlfredSOC   # add this
      # ...other skillsets...
```

If the agent is managed in the UI, edit it from the Agents page and
enable the new plugin under **Sources**.

### 6. Smoke-test

In a Security Copilot session with Alfred selected:

```
Show me CrowdStrike detections in the last 7 days for hostname WIN-LAPTOP-01.
```

```
Which assets in CrowdStrike are affected by CVE-2024-3094?
```

```
Run an NGSIEM search in the search-all repository for the last 24 hours
of PowerShell encoded-command launches on hostname WIN-LAPTOP-01.
```

You should see each skill invocation appear in the conversation’s
**Process log** with the skill name, the URL called, and a
non-2xx error if anything is wrong.

-----

## Common errors

|HTTP                             |Most likely cause                                      |Fix                                                                                          |
|---------------------------------|-------------------------------------------------------|---------------------------------------------------------------------------------------------|
|`401` on `/oauth2/token`         |Wrong client ID/secret, or wrong cloud                 |Re-check secret; confirm `FalconCloud` matches the cloud where the client was created        |
|`403` on any call                |Missing API scope on the Falcon API client             |Add the scope shown in the table above, regenerate the secret if required, update Copilot    |
|`403` on `StartNGSIEMSearch` only|`humio-auth-proxy:write` (UI: NGSIEM Write) not granted|Grant NGSIEM Write on the API client                                                         |
|`400` on `SearchAlertsByFQL`     |Bad FQL — quoting or unsupported field                 |Re-prompt the analyst to verify the filter; check the FQL examples in the OpenAPI description|
|`429`                            |Rate limit                                             |Falcon enforces ~6,000 req/min per CID. Throttle, retry with backoff                         |

-----

## Security notes

- The Falcon API secret is stored encrypted by Security Copilot, never
  in the manifest or OpenAPI spec.
- The plugin is purely a passthrough to Falcon REST APIs. No user data
  is stored client-side by the plugin itself.
- All actions are scoped read-only at the Falcon side. Even if Copilot
  were prompt-injected to “delete an alert”, the underlying API client
  has no write scopes (assuming the table above was followed) and the
  Falcon API would reject the call with 403.
- Rotate the Falcon API client secret on the cadence required by your
  policy; update Copilot via **Manage plugins → settings → reauthorize**.
