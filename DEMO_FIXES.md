# Demo Script Character Encoding Fixes

**Date:** 2026-02-04

## Issue

The demo scripts (`run-demo.bat` and `run-demo.sh`) were using Unicode characters that displayed incorrectly in Windows Command Prompt and some terminals:

- Box drawing characters: `╔`, `║`, `╚`, `═`
- Check marks: `✓`
- Info symbols: `ℹ`
- Warning symbols: `⚠`
- Emoji: `🎉`, `🛡️`

## Root Cause

Windows Command Prompt by default uses Code Page 437 (OEM US) which doesn't support these Unicode characters, causing them to display as weird symbols or question marks.

## Solution

Replaced all Unicode characters with ASCII equivalents that work reliably across all terminals:

### Character Mappings

| Before | After | Usage |
|--------|-------|-------|
| `╔═══╗` | `====` | Box borders |
| `║` | (removed) | Vertical borders |
| `╚═══╝` | `====` | Box borders |
| `═` | `=` | Horizontal lines |
| `✓` | `[OK]` | Success markers |
| `ℹ` | `[INFO]` | Information markers |
| `⚠` | `[WARNING]` | Warning markers |
| `•` | `-` | Bullet points |
| `🎉` | (removed) | Celebratory emoji |
| `🛡️` | (removed) | Shield emoji |

### Files Modified

1. **examples/run-demo.bat** (Windows)
   - Replaced box drawing with simple equals signs
   - Changed `echo ✓` to `echo [OK]`
   - Changed `echo ℹ` to `echo [INFO]`
   - Changed bullets from `•` to `-`
   - Removed emoji

2. **examples/run-demo.sh** (Linux/Mac)
   - Updated for consistency with Windows version
   - Replaced box drawing characters
   - Changed success/info/warning functions to use `[OK]`, `[INFO]`, `[WARNING]`
   - Changed bullets from `•` to `-`
   - Removed emoji

## Before Example

```
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║              DepGuard v2.0 Interactive Demo                   ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

✓ Initial scan complete!
ℹ Notice the ML Risk Scores
```

Displayed as:
```
É═══════════════════════════════════════════════════════════════╗
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

Γ£ö Initial scan complete!
Γäö Notice the ML Risk Scores
```

## After Example

```
================================================================

             DepGuard v2.0 Interactive Demo

  Data Flow Analysis + Machine Learning Risk Prediction

================================================================

[OK] Initial scan complete!
[INFO] Notice the ML Risk Scores
```

Displays correctly in all terminals! ✓

## Benefits

1. **Universal Compatibility** - Works on all terminals without special configuration
2. **No Encoding Issues** - Pure ASCII is universally supported
3. **Professional Appearance** - Clean, readable output
4. **Consistency** - Same appearance on Windows, Linux, and Mac
5. **Accessibility** - Screen readers work better with ASCII text

## Testing

Tested on:
- ✅ Windows Command Prompt (cmd.exe)
- ✅ Windows PowerShell
- ✅ Git Bash on Windows
- ✅ WSL Ubuntu
- ✅ macOS Terminal
- ✅ Linux terminals (bash, zsh)

All display correctly now!

## Alternative Solution (Not Implemented)

We could have added UTF-8 encoding to the Windows batch file:
```batch
chcp 65001 > nul
```

However, this approach has drawbacks:
- Changes global system settings
- May cause issues with other scripts
- Not all systems support UTF-8 properly
- Adds complexity

The ASCII solution is simpler and more reliable.

## Future Considerations

If we need fancy formatting in the future, consider:
1. Use ASCII art generators for consistency
2. Detect terminal capabilities and adapt output
3. Provide a `--fancy` flag for Unicode-capable terminals
4. Use color codes (already implemented in .sh) for visual distinction

## References

- Windows Code Pages: https://docs.microsoft.com/en-us/windows/win32/intl/code-pages
- ASCII Table: https://www.asciitable.com/
- Box Drawing ASCII alternatives: `+`, `-`, `|`, `=`

---

**Status:** ✅ Fixed
**Impact:** High - Improves user experience significantly
**Backward Compatible:** Yes
