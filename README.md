# CSF Service Blocklists (Mirror)

This is an automatically synced mirror of the official [ConfigServer Service Blocklists](https://github.com/ConfigServerApps/service-blocklists.git) repository.

## About

These blocklists are designed for use with [ConfigServer Security & Firewall (CSF)](https://configserver.com/cp/csf.html) and provide curated IP/network blocklists to help protect your server from known malicious sources. CSF uses these lists via the `csf.blocklists` configuration to populate ipset groups that are enforced at the firewall level.

## How It Works

- A GitHub Actions workflow runs every 6 hours to sync this fork with the upstream repository.
- The sync performs a hard reset against upstream to ensure this mirror is always an exact copy.
- Only the workflow file (`main.yml`) and this `README.md` are preserved from this fork — everything else comes directly from upstream.

## Usage

### In CSF

Reference the blocklists in `/etc/csf/csf.blocklists` on your server. After making changes, reload CSF:

```bash
csf -r
```

Verify a blocklist is loaded:

```bash
ipset list bl_CSF_MASTER
```

### As a Git Source

You can clone this mirror if you prefer pulling from your own account:

```bash
git clone https://github.com/YOUR-USERNAME/service-blocklists.git
```

## Upstream

**Original repository:** [https://github.com/ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists)

All credit for the blocklist content goes to [ConfigServer](https://configserver.com/). This mirror exists solely for convenience and automated syncing.

## Sync Schedule

| Event | Frequency |
|---|---|
| Automated sync | Every 6 hours |
| Manual sync | On-demand via Actions tab |

## License

This repository mirrors upstream content. Refer to the [original repository](https://github.com/ConfigServerApps/service-blocklists) for licensing information.
