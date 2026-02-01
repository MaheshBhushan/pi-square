# Pi-Square Extensions

Custom extensions for enhanced Pi functionality.

## Extensions

### 🔄 Multi-Account Antigravity (`multi-antigravity.ts`)

Manage multiple Google Antigravity accounts and automatically switch between them when rate limits or quota errors are detected.

**Features:**
- OAuth login for multiple accounts
- Automatic switching on rate limit (429) errors
- Manual switching via command or keyboard shortcut
- Token auto-refresh
- Persistent account storage

**Commands:**
| Command | Description |
|---------|-------------|
| `/antigravity:login` | Login to a new Antigravity account via OAuth |
| `/antigravity:list` | List all saved accounts |
| `/antigravity:switch` | Switch to a different account |
| `/antigravity:remove` | Remove an account |
| `/antigravity:clear` | Clear all accounts |

**Keyboard Shortcut:** `Ctrl+Shift+A` - Quick switch to next account

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

## Usage

### Multi-Account Workflow

1. Start Pi and run `/antigravity:login`
2. Complete OAuth in browser
3. Give the account a nickname
4. Repeat for additional accounts
5. Use `Ctrl+Shift+A` to switch or wait for auto-switch on rate limits

### Mode Workflow

1. Start in `/mode:plan` to analyze and plan
2. Review the generated plan
3. Switch to `/mode:build` to execute changes
4. Use `/mode:readonly` for code review without modifications
