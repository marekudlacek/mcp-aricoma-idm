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
- Set custom user attributes on groups (e.g. `notinoCustomAttribute2` for resource / competence flagging)
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
Create a new group. Supports `APPLICATION_GROUP` (no AD), `AD_SECURITY` and `AD_DISTRIBUTION` types. Optionally sets `notinoCustomAttribute2` (`resource` / `competence`) immediately after creation.

### `idm_change_group`
The main "update" tool — change multiple properties of an existing group in one call: name, type, scope, custom attribute, description, info, email, status.

### `idm_rename_group`
Simple rename of a group. Preserves attributes that are not explicitly overridden.

### `idm_set_group_attribute`
Set a user attribute on a group via `saveUserAttributeToEntity` (e.g. `AD_NOTINO_CUSTOM_ATTRIBUTE_2` = `resource` / `competence`).

### `idm_add_group_parent`
Add a parent record to a child group. Typical use case: a competence group (child) inherits permissions from a resource group (parent).

### `idm_remove_group_parent`
Remove a parent relationship between two groups.

## Usage Examples

Once configured, you can use natural-language commands with Claude:

- "Find groups containing 'Admin' in the NOTINO domain"
- "Show me the detail of the group G_DP_DEVELOPMENT_Specialist including members"
- "Create a new AD Security group G_NEW_TEAM with GLOBAL scope and notinoCustomAttribute2 = resource"
- "Add user jan.novak to group G_DP_DEVELOPMENT_Specialist"
- "Rename group G_OLD_NAME to G_NEW_NAME and set notinoCustomAttribute2 to competence"
- "Add parent record d_special_heads to group G_DP_DEVELOPMENT_Specialist"
- "Remove user jan.novak from group G_DP_DEVELOPMENT_Specialist"
- "Show detail of user marek.kudlacek in NOTINO"

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
| `IDM_GUID_SYSTEM` | Yes | GUID of the calling system in IDM (assigned by IDM admin) |
| `IDM_LOGIN` | Yes | Service account login for IDM |
| `IDM_PASSWORD` | Yes | Service account password |

The IDM endpoint URL is currently hard-coded to `https://idm.notino.com/IDM/ExternalInterface?wsdl` in `idm_mcp.py`. If you deploy against a different IDM instance, change the `IDM_ENDPOINT` constant.

## Setup for Claude Code

Add to your `~/.claude.json` or your project's `.claude.json`:

```json
{
  "mcpServers": {
    "idm": {
      "command": "python",
      "args": ["/path/to/idm_mcp.py"],
      "env": {
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password"
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
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password"
      }
    }
  }
}
```

# Setup for Claude Desktop

## Quick Install via CLI

You can add this MCP server directly using the `claude mcp add` command.

### With uv (recommended):

```bash
claude mcp add --transport stdio idm \
  --env IDM_GUID_SYSTEM=your-guid-system \
  --env IDM_LOGIN=your-service-login \
  --env IDM_PASSWORD=your-service-password \
  -- uv run --with requests --with mcp python /path/to/idm_mcp.py
```

### With python:

```bash
claude mcp add --transport stdio idm \
  --env IDM_GUID_SYSTEM=your-guid-system \
  --env IDM_LOGIN=your-service-login \
  --env IDM_PASSWORD=your-service-password \
  -- python /path/to/idm_mcp.py
```

### Manage MCP servers:

```bash
# List all configured servers
claude mcp list

# Get details for a specific server
claude mcp get idm

# Remove a server
claude mcp remove idm
```

## Install via CONFIG FILES

Add to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "idm": {
      "command": "python",
      "args": ["/path/to/idm_mcp.py"],
      "env": {
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password"
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
        "IDM_GUID_SYSTEM": "your-guid-system",
        "IDM_LOGIN": "your-service-login",
        "IDM_PASSWORD": "your-service-password"
      }
    }
  }
}
```

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
