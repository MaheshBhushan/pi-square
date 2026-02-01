# Pi-Square Extensions

Custom extensions for enhanced Pi functionality.

## Extensions

### 🔄 Multi-Account Antigravity (`multi-antigravity.ts`)

Manage multiple Google Antigravity accounts with **token-based round-robin** distribution. Automatically switches accounts to distribute usage evenly and avoid rate limits.

**Features:**
- **Token-based round-robin**: Switch accounts after token threshold
- **Smart account selection**: Picks account with lowest usage
- **Rate limit fallback**: Auto-switch on quota errors
- **Token tracking**: Monitor usage per account
- **Configurable thresholds**: Set token limits and reset periods
- **Progress display**: See usage in status bar

**Commands:**
| Command | Description |
|---------|-------------|
| `/antigravity:login` | Login to a new Antigravity account via OAuth |
| `/antigravity:list` | List all accounts with token usage & progress bars |
| `/antigravity:switch` | Switch to a different account |
| `/antigravity:usage` | Show detailed token usage statistics |
| `/antigravity:config` | Configure threshold, reset period, strategy |
| `/antigravity:reset` | Reset token counters for all accounts |
| `/antigravity:remove` | Remove an account |
| `/antigravity:clear` | Clear all accounts |

**Configuration Options:**
| Setting | Default | Description |
|---------|---------|-------------|
| Token Threshold | 50,000 | Switch after N tokens |
| Reset Period | daily | When to reset counters (hourly/daily/never) |
| Strategy | token | Round-robin strategy (token/request/manual) |

**Keyboard Shortcut:** `Ctrl+Shift+A` - Quick switch to next account

**Status Bar:** Shows current account and usage: `🔄 account1: 25K/50K (50%)`

---

### 🎯 Mode Switcher (`mode-switcher.ts`)

Switch between different operational modes with tool restrictions and system prompt injection.

**Modes:**
| Mode | Emoji | Tools | Description |
|------|-------|-------|-------------|
| **BUILD** | 🔨 | All tools | Normal coding mode (default) |
| **PLAN** | 📋 | Read-only | Autonomous planning with structured reasoning |
| **READ-ONLY** | 👁️ | Read-only | Analysis and review only |

**Commands:**
| Command | Description |
|---------|-------------|
| `/mode` | Show current mode |
| `/mode:plan` | Switch to planning mode |
| `/mode:build` | Switch to build mode |
| `/mode:readonly` | Switch to read-only mode |

**Keyboard Shortcut:** `Ctrl+Shift+M` - Cycle through modes

**Plan Mode Features:**
- Autonomous agent behavior
- Breaks tasks into clear sub-tasks
- Executes sequentially and logically
- Produces structured output with conclusions
- Read-only (no file modifications until switching to BUILD mode)

---

## Installation

Copy the extension files to your Pi extensions directory:

```bash
cp pi-square-extensions/*.ts ~/.pi/agent/extensions/
```

Then reload Pi:
```
/reload
```

## Token-Based Round-Robin Example

```
# Login to multiple accounts
/antigravity:login    # Login as account1
/antigravity:login    # Login as account2
/antigravity:login    # Login as account3

# Configure threshold (optional)
/antigravity:config   # Set to 30K tokens per account

# Usage is automatically tracked
# When account1 hits 30K tokens → switches to account2
# When account2 hits 30K tokens → switches to account3
# And so on...

# View usage stats
/antigravity:usage

# Output:
# 📊 Total Usage Summary
# ━━━━━━━━━━━━━━━━━━━━
# Total Tokens: 75K
# Total Requests: 45
# 
# → account1:
#   [████████░░] 28K/30K (93%)
#   
#   account2:
#   [██████░░░░] 25K/30K (83%)
#   
#   account3:
#   [████░░░░░░] 22K/30K (73%)
```

## Usage Workflow

### Multi-Account Setup

1. Start Pi and run `/antigravity:login`
2. Complete OAuth in browser
3. Give the account a nickname
4. Repeat for additional accounts
5. Configure threshold with `/antigravity:config`
6. Use normally - accounts rotate automatically

### Mode Workflow

1. Start in `/mode:plan` to analyze and plan
2. Review the generated plan
3. Switch to `/mode:build` to execute changes
4. Use `/mode:readonly` for code review without modifications
