# Skyrim exact inputs

These hashes identify the privately owned generation inputs. No executable or
Address Library database is redistributed.

## Executables

| Profile | File size | SHA-256 |
|---|---:|---|
| Skyrim SE 1.5.97.0 | 34,769,792 | `5666e1bddd01bcab31ecf11691ef1a3f22e1541af79f2bc0e55318533cfe5d12` |
| Skyrim AE 1.6.1170.0 | 36,950,016 | `80c1ea737d33c6bfac09b101b8d77ab0f9f6630128c3ed052f9d945bed54e7e4` |
| Skyrim GOG ProductVersion 1.6.1179.0 | 36,958,208 | `9b0fc7880c4b12d436bfb59bcae64868f176dbc04010adbd9bc2ecb64bc8ed3f` |
| Skyrim VR 1.4.15.0 decrypted generation image | 35,531,264 | `3de757b7f52f82551fc73c5ff1d0592f69d03ecc7f492b712a24c6a957cc2e24` |
| Skyrim VR 1.4.15.0 official encrypted on-disk image, identification only | 35,530,960 | `6961efb4f4775a307b0fc9a3d637542c1e090be207d3b09467eab216b7f87971` |

The GOG ProductVersion is 1.6.1179.0; SKSE uses the storefront-tagged runtime
value 1.6.1179.1. The decrypted VR image is the static generation input. Runtime
byte gates still verify the live decrypted code before writing.

## Address Library inputs

| Profile | File | Size | SHA-256 |
|---|---|---:|---|
| SE 1.5.97 | `version-1-5-97-0.bin` | 1,490,796 | `1d7530d001139ca58f462ea0210a8055868159057ba8b5ebc624fc5e9c4f5e9a` |
| AE 1.6.1170 | `versionlib-1-6-1170-0.bin` | 795,129 | `c4093c569a3c83b26587f4b9ea4c55de9ae6e73b84a2af9fb3fbd30e2fe0d452` |
| GOG 1.6.1179 | `versionlib-1-6-1179-0.bin` | 796,422 | `3ee46b2f3a8a24b9cda1f2aa63b0f0f47dea347e52701a6739327e5ea1b5838e` |
| VR 1.4.15 | full `version-1-4-15-0.csv` export | 221,460 | `a911a457eb05be52560e591b7d310d0097fc42c414d13c3d4362481b8bea42ac` |

Generated header:

- `src/PatchTable.g.h`: `4a32b4958018ba2d85b2347adc0557e74e2202cc3a859f9861612d6f7ce1f50e`
