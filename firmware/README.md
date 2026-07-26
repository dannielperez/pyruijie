# Ruijie Firmware Repository

This directory is the controlled local repository for Ruijie/Reyee firmware
artifacts. `catalog.json` is the source of truth for approved device-specific
upgrade paths.

The catalog intentionally starts with metadata only. Do not rename a random
download to match a catalog entry. Before an image can be used:

1. Obtain the exact firmware image from an authorized Ruijie/Reyee source.
2. Record its original filename and SHA-256 in `catalog.json`.
3. Change the artifact `state` from `metadata-only` to `approved`.
4. Run `pyruijie firmware verify`.
5. Validate the image on one canary bridge with an out-of-band recovery path.

Firmware binaries are ignored by Git by default. Store them in an access-
controlled artifact bucket or enable Git LFS deliberately if redistribution and
repository size policies allow it.

Current initial policy:

- `EST100-E` on `AP_3.0(1)B11P96,Release(11132319)` needs the approved
  `AP_3.0(1)B11P320,Release(12152011)` compatibility image.
- B11P327 and B11P380 are recognized because they already appear on
  cloud-managed EST100-E devices, but they are not selected as the B11P96
  bootstrap image. “Newest” is not used as an upgrade rule.
- A different EST100-E version is reported as `manual_review`, not treated as
  “older” or automatically upgraded.
- Unknown models are never assigned an image.
