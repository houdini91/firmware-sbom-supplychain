# uefi/scan_image: fix ImportError — BIOS not exported by chipsec.hal.intel.spi

> Draft body for a **standalone** bugfix PR against `chipsec/chipsec` (`chipsec2`),
> independent of the normalized-hash feature PR. Trivial, obvious bug → a direct PR is
> appropriate (no design discussion needed). NOT filed yet — owner-gated.
> Branch: `houdini91:fix/scan-image-spi-import`.

## Summary

`chipsec/modules/tools/uefi/scan_image.py` fails to import on `chipsec2`:

```python
from chipsec.hal.intel.spi import SPI, BIOS   # BIOS is not defined here
```

`BIOS` is not exported by `chipsec.hal.intel.spi`, so importing the module raises
`ImportError` — `tools.uefi.scan_image` cannot be loaded or run as-is. `BIOS` is
already imported from `chipsec.module_common` on the **preceding** line, and the
module's two uses of it — `TAGS = [BIOS]` and `self.spi.get_SPI_region(BIOS)` —
resolve correctly from that import. This PR drops `BIOS` from the
`chipsec.hal.intel.spi` import so the module loads again.

## Change (one line)

| File | Before | After |
| --- | --- | --- |
| `chipsec/modules/tools/uefi/scan_image.py` | `from chipsec.hal.intel.spi import SPI, BIOS` | `from chipsec.hal.intel.spi import SPI` |

## Behavior

- **Before:** `import chipsec.modules.tools.uefi.scan_image` → `ImportError` (BIOS
  undefined in `chipsec.hal.intel.spi`).
- **After:** module imports cleanly; `BIOS` resolves from `chipsec.module_common`
  (already imported one line up). No functional change — `TAGS` and
  `get_SPI_region(BIOS)` are unchanged.

Commit is DCO `Signed-off-by`. Independent of the `scan_image` normalized-hash
feature PR (which notes this bug and links here).
