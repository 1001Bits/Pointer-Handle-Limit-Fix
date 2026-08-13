# Starfield exact inputs

These hashes identify the privately owned inputs used during development and
review. The files themselves are not redistributed.

| Role | File | Size | SHA-256 |
|---|---|---:|---|
| Supported runtime image | `Starfield.exe` 1.16.236.0 | 102,507,432 | `1d1409ca898ca596a3a605f3ebc5347f72cfd6e47e38020dec158ec9bdd7d351` |
| Matching Address Library | `versionlib-1-16-236-0.bin` | 4,571,884 | `ab42252c1b8308897e9a2374c0e717dadbfd0e5cec514df809f1a7c26f930c43` |
| Supported runtime image | `Starfield.exe` 1.16.244.0 | 102,476,200 | `7e9adb1414a8e1b325e5e1f097b9b17b78deb7eebeda37a333351a43a60f9d28` |
| Matching Address Library | `versionlib-1-16-244-0.bin` | 5,099,968 | `299ea1b4da35b42e9bf1b8ed94fa980694a4dcbebfc7693201619c4c08fa49d8` |

## Address Library mapping used by the production and test sources

All values are RVAs from image base `0x140000000`.

| ID | Purpose | 1.16.236 RVA | 1.16.244 RVA |
|---:|---|---:|---:|
| `883285` | handle-manager singleton pointer | `0x5E68140` | `0x5E60380` |
| `36239` | reference lookup | `0x2CF360` | `0x2CEC10` |
| `450711` | handle-manager primary vtable | `0x4CB6D88` | `0x4CB2E98` |
| `99517` | native-handle assignment callback | `0x18A2090` | `0x189F8D0` |
| `139362` | core handle creator, live test only | `0x28D0E40` | — |
| `139363` | core handle resolver, audit only | `0x28D0FF0` | `0x28CCC40` |
| `139364` | core handle releaser, live test only | `0x28D1090` | — |

Release v1.0.1 modular source/configuration hashes:

- `src/` manifest: `7e9ae7e65c6da35812e8e1afe482d4ef6848991226dd5606dcb71b998be37761`
  - computed as SHA-256 of UTF-8 lines `filename=lowercase_file_sha256\n`, sorted by filename
- `CMakeLists.txt`: `5f622fb53afd859bfd0feb8bca26d17017ffd3bae16b5605e34347e245bca6a6`
- `vcpkg.json`: `12d60f26639d6598483d9e7619f23fa8c5d8188f957127e8a378f321cd1acdcc`
- `StarfieldHandleCapRaise.ini`: `6c00badb57270a336a72f95380493558395c52e9f6ea7f77f031354f8dc2f5ed`

Release v1.0.1 modular artifact hashes:

- `StarfieldHandleCapRaise.dll`: `d67a84ab8a9d92ea607a006c77f65663b83f9576ac5128fd0c7396bc07f336c0`
- `PointerHandleLimitFix-v1.0.1.zip`: `ae4060ddb9115ad616a37b7f5a60cbb1253aab0f1586ba927f136166a1538e59`
- `PointerHandleLimitFix-v1.0.1.7z`: `697dec69b5d5899e012dddacd9af8189f17b0956c339cf74836c6443e9791136`

Hash-bound modular in-game smoke evidence:

- `SMOKE-RESULT.txt`: `c9dc46fba18137fc053f31510b5618a26b7c5c55f56ac285b7fc36a6e432f743`
- `StarfieldHandleCapRaise.log`: `cb69f4ae557b8acd1d47a335e21b2af8fb375ddf14dc5ec08a617c7dec6924e5`

Test-only v1.0.1 verification artifacts (not shipped in the release archives):

- `tests/model_stress/main.cpp`: `054239689133f919b260e312e8475f9dadae0e8c1275a51c6a3ca12863d8b266`
- `StarfieldHandleModelStress.exe`: `37d3d0d44d4dd9b12591db61645b277c08aab85c9a3fbc393e231953b35c5001`
- `tests/live_stress/src/main.cpp`: `99867933cec97d59b48783018d96d0203a501ab387064dd20a6912d4380c309e`
- `StarfieldHandleLiveStress.dll`: `f1ea25f3b54069934892d706a3dc49fa67b7acd14514d51b877cf277341f2e16`

Captured live-stress evidence:

- `RESULT.txt`: `54bef114bd79138b6ee5561f254f8760a1dc92afe5f376c63dee06fa0f1b3c55`
- `sfse.txt`: `b2c2c5ad4e6fdcf77937a25f36864dc1aa11878d7a68b8b2f09346246849040d`
- `StarfieldHandleCapRaise.log`: `f86d456305723293d58f6f1d0ab2e088931e2afa11c67ce688305e72e7ff6d76`
- `StarfieldHandleLiveStress.log`: `5d924ab5f43ee86324b8f9905c5d994fdc86e3b6d7b7d76097d9272e94bdde15`
