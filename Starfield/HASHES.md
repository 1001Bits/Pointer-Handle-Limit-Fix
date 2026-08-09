# Starfield exact inputs

These hashes identify the privately owned inputs used during development and
review. The files themselves are not redistributed.

| Role | File | Size | SHA-256 |
|---|---|---:|---|
| 1.16.236 audit image | `Starfield.exe` 1.16.236.0 | 102,507,432 | `1d1409ca898ca596a3a605f3ebc5347f72cfd6e47e38020dec158ec9bdd7d351` |
| 1.16.236 Address Library | `versionlib-1-16-236-0.bin` | 4,571,884 | `ab42252c1b8308897e9a2374c0e717dadbfd0e5cec514df809f1a7c26f930c43` |
| 1.16.244 release image | `Starfield.exe` 1.16.244.0 | 102,476,200 | `7e9adb1414a8e1b325e5e1f097b9b17b78deb7eebeda37a333351a43a60f9d28` |
| 1.16.244 Address Library | `versionlib-1-16-244-0.bin` | 5,099,968 | `299ea1b4da35b42e9bf1b8ed94fa980694a4dcbebfc7693201619c4c08fa49d8` |

## Address Library mapping used by the source

All values are RVAs from image base `0x140000000`.

| ID | Purpose | 1.16.236 RVA | 1.16.244 RVA |
|---:|---|---:|---:|
| `883285` | handle-manager singleton pointer | `0x5E68140` | `0x5E60380` |
| `36239` | reference lookup | `0x2CF360` | `0x2CEC10` |
| `450711` | handle-manager primary vtable | `0x4CB6D88` | `0x4CB2E98` |
| `99517` | native-handle assignment callback | `0x18A2090` | `0x189F8D0` |
| `139363` | core handle resolver, audit only | `0x28D0FF0` | `0x28CCC40` |

Snapshot source hash:

- `src/main.cpp`: `4ed0201c75026152ad3438338d18d1877f6d8b2581de8c4b0753d840a3f9bbe5`
