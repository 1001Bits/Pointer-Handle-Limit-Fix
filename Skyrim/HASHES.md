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

- `src/PatchTable.g.h` (2M/21+5): `bbbbfc29953ce4da537d2781637d42f316e5ed7eded7f7348ebde8cc2fccab0f`

Generated profiles:

| Profile | SHA-256 |
|---|---|
| SE | `8caa63a0d5c30d59879425bd35b24a08d84a9087b9ec41566451b189cc382aec` |
| AE | `df6d1f4da56890273b251b67565dfd0b7ce35aeff639a48e68faa965c4834978` |
| GOG | `adc72b15e9c2a36e27749e2f511ba507196d93a060a92a3098321c802458c39c` |
| VR | `766cd35f1044018ecab7265cd98e50089db36f09f9873dc39eb08cb0e9f4a794` |

These are architecture-generation inputs, not final release-package pins. The
candidate DLL and ZIP are recorded only after two clean reproducible builds and
the fresh live gates authenticate the same bytes.
