# ARICOMA IDM MCP Server

MCP (Model Context Protocol) server for **ARICOMA Identity Management (IDM)**. Enables AI assistants like Claude to interact with IDM over its SOAP `ExternalInterface` — search groups and users, manage group membership, create and update groups, manage group hierarchy, and set custom attributes.

## About ARICOMA Identity Management

[ARICOMA Identity Management](https://www.aricoma.com/solutions/enterprise-cybersecurity/identity-%C2%A0access-management/identity-management-idm-ad-ldap) (also marketed as **AC Identita**) is an enterprise IAM solution from the Czech company [ARICOMA](https://www.aricoma.com/). It centralizes identity, role and permission management across the entire lifecycle and integrates with AD/LDAP and other downstream systems.

This MCP server talks to IDM via the official SOAP web service at `/IDM/ExternalInterface?wsdl`.

> **Disclaimer:** This project is not an official ARICOMA product. It is a community-built MCP server on top of the publicly documented IDM SOAP API. ARICOMA, AC Identita and IDM are trademarks of their respective owners.

## Is there an official MCP server for ARICOMA IDM?

Based on public sources (the official [MCP Registry](https://registry.modelcontextprotocol.io/), GitHub, ARICOMA's website), **no official or community MCP server for ARICOMA Identity Management / AC Identita has been published** at the time of writing. This repository is likely the first publicly available MCP server for this ecosystem.

## Features

- Search groups by domain, organization, status and name fragment
- Get full group detail including members
- Search and look up users by login or email
- Add and remove users to/from groups
- Create new groups (`APPLICATION_GROUP`, `AD_SECURITY`, `AD_DISTRIBUTION`)
- Rename groups and change group attributes (type, scope, description, email, status…)
- Set custom user attributes on groups (e.g. `customAttribute2` for resource / competence flagging)
- Manage hierarchical group relationships (parent records)
- Automatic session re-authentication when the IDM session expires

## Available Tools

### `idm_search_groups`
Search groups by organization, domain, status and a name fragment. Recommended to always pass `name_contains` — the IDM list endpoint is slow without filtering.

### `idm_get_group_detail`
Get full group detail including members. **The fastest way** to look up a group when you know its name.

### `idm_search_users`
Search users by organization, domain, status and user type.

### `idm_get_user_detail`
Get full detail of a user by login or email.

### `idm_add_user_to_group`
Add a user to a group.

### `idm_remove_user_from_group`
Remove a user from a group.

### `idm_create_group`
Create a new group. Supports `APPLICATION_GROUP` (no AD), `AD_SECURITY` and `AD_DISTRIBUTION` types. Optionally sets `customAttribute2` (`resource` / `competence`) immediately after creation.

### `idm_change_group`
The main "update" tool — change multiple properties of an existing group in one call: name, type, scope, custom attribute, description, info, email, status.

### `idm_rename_group`
Simple rename of a group. Preserves attributes that are not explicitly overridden.

### `idm_set_group_attribute`
Set a user attribute on a group via `saveUserAttributeToEntity` (e.g. `AD_CUSTOM_ATTRIBUTE_2` = `resource` / `competence`).

### `idm_add_group_parent`
Add a parent record to a child group. Typical use case: a competence group (child) inherits permissions from a resource group (parent).

### `idm_remove_group_parent`
Remove a parent relationship between two groups.

## Usage Examples

Once configured, you can use natural-language commands with Claude:

- "Find groups containing 'Admin' in the ACME domain"
- "Show me the detail of the group G_DP_DEVELOPMENT_Specialist including members"
- "Create a new AD Security group G_NEW_TEAM with GLOBAL scope and customAttribute2 = resource"
- "Add user jan.novak to group G_DP_DEVELOPMENT_Specialist"
- "Rename group G_OLD_NAME to G_NEW_NAME and set customAttribute2 to competence"
- "Add parent record d_special_heads to group G_DP_DEVELOPMENT_Specialist"
- "Remove user jan.novak from group G_DP_DEVELOPMENT_Specialist"
- "Show detail of user marek.kudlacek in the ACME domain"

### End-to-end example: creating a group with attributes and a parent record

Real prompt the agent received:

> **Please create in IDM group:**
>
> - **NAME:** `G_MARA_TEST`
> - **GROUP TYPE:** `AD Security`
> - **GROUP SCOPE:** `Global`
> - **EMAIL:** `g.mara.test@marekudlacek.cz`
> - **CUSTOMATTRIBUTE2:** `organization team`
> - **PARENT RECORDS:** `G_MARA`

Under the hood Claude orchestrates **two MCP tool calls** in sequence:

1. **`idm_create_group`** — creates the group, sets type/scope/email and `customAttribute2` in one shot (the tool internally chains `createUserGroup` + `saveUserAttributeToEntity`):

   ```json
   {
     "name": "G_MARA_TEST",
     "group_type": "AD_SECURITY",
     "group_scope": "GLOBAL",
     "email": "g.mara.test@marekudlacek.cz",
     "custom_attribute_2": "organization team"
   }
   ```

2. **`idm_add_group_parent`** — attaches `G_MARA` as a parent record (this step is not part of `createUserGroup` in the IDM SOAP API and must be done separately):

   ```json
   {
     "child_group_name": "G_MARA_TEST",
     "parent_group_name": "G_MARA"
   }
   ```

Result in AC Identita UI — group `G_MARA_TEST` is created as `AD Security / Global`, with the correct e-mail and `customAttribute2` set, and `G_MARA` linked as a parent on the **Parent records** tab:

![G_MARA_TEST created via the MCP server, shown in AC Identita](docs/screenshots/g_mara_test.png)

## Requirements

- Python 3.10+
- Claude (Code or Desktop), or any other MCP-compatible client
- Access to an ARICOMA IDM instance with the `ExternalInterface` SOAP service enabled
- IDM service credentials (`guidSystem`, login, password)

## Installing uv (Recommended)

`uv` is an extremely fast Python package manager that simplifies running MCP servers. With `uv`, you don't need to manually create virtual environments or install dependencies — it handles everything automatically.

### macOS / Linux

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### macOS (Homebrew)

```bash
brew install uv
```

### Windows

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Verify installation

```bash
uv --version
```

> **Note:** Using `uv` is optional but recommended. If you prefer not to use it, you can use the standard `python` + `pip install` approach instead.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/marekudlacek/mcp-aricoma-idm.git
cd mcp-aricoma-idm
```

2. Install dependencies (! only when uv is not used !):
```bash
pip install -r requirements.txt
```

## Configuration

Set the following environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `IDM_ENDPOINT` | Yes | Full URL of the IDM SOAP endpoint (e.g. `https://idm.your-company.com/IDM/ExternalInterface?wsdl`) |
| `IDM_GUID_SYSTEM` | Yes | GUID of the calling system in IDM (assigned by IDM admin) |
| `IDM_LOGIN` | Yes | Service account login for IDM |
| `IDM_PASSWORD` | Yes | Service account password |
| `IDM_DEFAULT_DOMAIN` | No | Default IDM domain code used when a tool is invoked without `domain_code` (e.g. `ACME`). Leave empty to require explicit specification. |
| `IDM_CUSTOM_ATTRIBUTE_2_CODE` | No | Attribute code used by the `custom_attribute_2` parameter in `idm_create_group` / `idm_change_group`. Tenant-specific. Default: `AD_CUSTOM_ATTRIBUTE_2`. |

## Setup for Claude Code

Add to your `~/.claude.json` or your project's `.claude.json`:

```json
{
  "mcpServers": {
    "idm": {
      "command": "python",
      "args": ["/path/to/idm_mcp.py"],
      "env": {
        "IDM_ENDPOINT": "https://idm.your-company.com/IDM/ExternalInterface?wsdl",
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password",
        "IDM_DEFAULT_DOMAIN": "ACME",
        "IDM_CUSTOM_ATTRIBUTE_2_CODE": "AD_CUSTOM_ATTRIBUTE_2"
      }
    }
  }
}
```

Or with `uv` (recommended):

```json
{
  "mcpServers": {
    "idm": {
      "command": "uv",
      "args": [
        "run",
        "--with", "requests",
        "--with", "mcp",
        "python",
        "/path/to/idm_mcp.py"
      ],
      "env": {
        "IDM_ENDPOINT": "https://idm.your-company.com/IDM/ExternalInterface?wsdl",
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password",
        "IDM_DEFAULT_DOMAIN": "ACME",
        "IDM_CUSTOM_ATTRIBUTE_2_CODE": "AD_CUSTOM_ATTRIBUTE_2"
      }
    }
  }
}
```

### Alternative: install via the `claude` CLI

If you have the Claude Code CLI installed, you can register the server with a single command instead of editing JSON by hand.

#### With uv (recommended):

```bash
claude mcp add --transport stdio idm \
  --env IDM_ENDPOINT=https://idm.your-company.com/IDM/ExternalInterface?wsdl \
  --env IDM_GUID_SYSTEM=your-guid-system \
  --env IDM_LOGIN=your-service-login \
  --env IDM_PASSWORD=your-service-password \
  --env IDM_DEFAULT_DOMAIN=ACME \
  --env IDM_CUSTOM_ATTRIBUTE_2_CODE=AD_CUSTOM_ATTRIBUTE_2 \
  -- uv run --with requests --with mcp python /path/to/idm_mcp.py
```

#### With python:

```bash
claude mcp add --transport stdio idm \
  --env IDM_ENDPOINT=https://idm.your-company.com/IDM/ExternalInterface?wsdl \
  --env IDM_GUID_SYSTEM=your-guid-system \
  --env IDM_LOGIN=your-service-login \
  --env IDM_PASSWORD=your-service-password \
  --env IDM_DEFAULT_DOMAIN=ACME \
  --env IDM_CUSTOM_ATTRIBUTE_2_CODE=AD_CUSTOM_ATTRIBUTE_2 \
  -- python /path/to/idm_mcp.py
```

#### Manage MCP servers:

```bash
# List all configured servers
claude mcp list

# Get details for a specific server
claude mcp get idm

# Remove a server
claude mcp remove idm
```

> **Note:** `claude mcp add` is a feature of the **Claude Code CLI** — it does not modify the Claude Desktop config. For Claude Desktop see the next section.

## Setup for Claude Desktop

Claude Desktop is configured exclusively through its config file — there is no CLI installer.

### 1. Open the config file

In Claude Desktop click **Developer** in the left sidebar → **Edit Config**. This opens (or creates) the config file at the following paths:

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

### 2. Add the IDM server entry

Paste the `idm` block inside `mcpServers`. If the file is empty, use the full snippet below as-is.

With `python`:

```json
{
  "mcpServers": {
    "idm": {
      "command": "python",
      "args": ["/path/to/idm_mcp.py"],
      "env": {
        "IDM_ENDPOINT": "https://idm.your-company.com/IDM/ExternalInterface?wsdl",
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password",
        "IDM_DEFAULT_DOMAIN": "ACME",
        "IDM_CUSTOM_ATTRIBUTE_2_CODE": "AD_CUSTOM_ATTRIBUTE_2"
      }
    }
  }
}
```

Or with `uv` (recommended):

```json
{
  "mcpServers": {
    "idm": {
      "command": "uv",
      "args": [
        "run",
        "--with", "requests",
        "--with", "mcp",
        "python",
        "/path/to/idm_mcp.py"
      ],
      "env": {
        "IDM_ENDPOINT": "https://idm.your-company.com/IDM/ExternalInterface?wsdl",
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password",
        "IDM_DEFAULT_DOMAIN": "ACME",
        "IDM_CUSTOM_ATTRIBUTE_2_CODE": "AD_CUSTOM_ATTRIBUTE_2"
      }
    }
  }
}
```

### 3. Restart Claude Desktop

Quit Claude Desktop completely and reopen it. The `idm_*` tools should now be available — verify them in the **Developer** tab.

## Performance Tips

- Always use `idm_get_group_detail` when you know the group name — orders of magnitude faster than `idm_search_groups`.
- For `idm_search_groups`, always pass `name_contains` (otherwise the whole domain is downloaded).
- For `idm_search_users`, always pass at least `status="ACTIVE"`.

## Security

- Credentials live in the client's config file — protect it and **do not commit** it.
- The server only talks to the IDM endpoint over HTTPS. SSL verification is disabled in `idm_mcp.py` (`verify=False`) to support internal CAs — adjust if you have a trusted certificate chain.
- Use a dedicated service account in IDM with the minimum required permissions.

## License

MIT License
