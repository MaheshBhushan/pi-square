/**
 * Multi-Account Antigravity Extension with Token-Based Round-Robin
 *
 * Manages multiple Google Antigravity accounts and automatically switches
 * between them using token-based round-robin distribution.
 *
 * FEATURES:
 * - Token-based round-robin: Switch accounts after token threshold
 * - Rate limit fallback: Auto-switch on quota errors
 * - Token tracking: Monitor usage per account
 * - Configurable thresholds: Set token limits per account
 *
 * COMMANDS:
 * - /antigravity:login    - Login to a new Antigravity account via OAuth
 * - /antigravity:list     - List all saved accounts with token usage
 * - /antigravity:switch   - Switch to a different account
 * - /antigravity:remove   - Remove an account
 * - /antigravity:clear    - Clear all accounts
 * - /antigravity:config   - Configure token threshold and reset period
 * - /antigravity:usage    - Show detailed token usage stats
 * - /antigravity:reset    - Reset token counters for all accounts
 *
 * KEYBOARD:
 * - Ctrl+Shift+A - Quick switch to next account
 *
 * ROUND-ROBIN:
 * Accounts are rotated based on token usage. When an account reaches
 * the configured threshold, it automatically switches to the next account.
 * Token counters reset based on the configured reset period (hourly/daily).
 */

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as http from "node:http";
import * as crypto from "node:crypto";

interface AntigravityCredentials {
  type: "oauth";
  refresh: string;
  access: string;
  expires: number;
  projectId: string;
  email?: string;
}

interface TokenUsage {
  input: number;
  output: number;
  total: number;
  lastReset: number;
  requestCount: number;
}

interface AccountEntry {
  id: string;
  projectId: string;
  credentials: AntigravityCredentials;
  addedAt: number;
  lastUsed?: number;
  nickname: string;
  email?: string;
  tokenUsage: TokenUsage;
}

interface RoundRobinConfig {
  tokenThreshold: number;      // Switch after this many tokens (default: 50000)
  resetPeriod: "hourly" | "daily" | "never";  // When to reset counters
  strategy: "token" | "request" | "manual";   // Round-robin strategy
  requestThreshold: number;    // For request-based strategy
}

interface MultiAccountState {
  accounts: AccountEntry[];
  currentIndex: number;
  config: RoundRobinConfig;
  lastConfigUpdate: number;
}

const PI_DIR = path.join(os.homedir(), ".pi", "agent");
const AUTH_FILE = path.join(PI_DIR, "auth.json");
const STATE_FILE = path.join(PI_DIR, "multi-antigravity-state.json");

// Default configuration
const DEFAULT_CONFIG: RoundRobinConfig = {
  tokenThreshold: 50000,       // 50k tokens before switching
  resetPeriod: "daily",        // Reset counters daily
  strategy: "token",           // Token-based round-robin
  requestThreshold: 20,        // 20 requests for request-based
};

// Antigravity OAuth config - matches Pi's internal config
const OAUTH_CONFIG = {
  clientId: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
  clientSecret: "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",
  authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUrl: "https://oauth2.googleapis.com/token",
  redirectUri: "http://localhost:51121/oauth-callback",
  redirectPort: 51121,
  scopes: [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
  ],
  defaultProjectId: "rising-fact-p41fc",
};

function createEmptyTokenUsage(): TokenUsage {
  return {
    input: 0,
    output: 0,
    total: 0,
    lastReset: Date.now(),
    requestCount: 0,
  };
}

function loadState(): MultiAccountState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const data = JSON.parse(fs.readFileSync(STATE_FILE, "utf-8"));
      // Ensure config exists
      if (!data.config) {
        data.config = { ...DEFAULT_CONFIG };
      }
      // Ensure all accounts have tokenUsage
      for (const account of data.accounts || []) {
        if (!account.tokenUsage) {
          account.tokenUsage = createEmptyTokenUsage();
        }
      }
      return data as MultiAccountState;
    }
  } catch (e) {
    // Ignore
  }
  return { 
    accounts: [], 
    currentIndex: 0, 
    config: { ...DEFAULT_CONFIG },
    lastConfigUpdate: Date.now(),
  };
}

function saveState(state: MultiAccountState): void {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function loadAuthJson(): Record<string, any> {
  try {
    if (fs.existsSync(AUTH_FILE)) {
      return JSON.parse(fs.readFileSync(AUTH_FILE, "utf-8"));
    }
  } catch (e) {
    // Ignore
  }
  return {};
}

function saveAuthJson(auth: Record<string, any>): void {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), { mode: 0o600 });
}

function setAntigravityCredentials(creds: AntigravityCredentials): void {
  const auth = loadAuthJson();
  auth["google-antigravity"] = creds;
  saveAuthJson(auth);
}

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 6);
}

// Check if token counters should be reset based on period
function shouldResetTokens(lastReset: number, period: "hourly" | "daily" | "never"): boolean {
  if (period === "never") return false;
  
  const now = Date.now();
  const hourMs = 60 * 60 * 1000;
  const dayMs = 24 * hourMs;
  
  if (period === "hourly") {
    return now - lastReset > hourMs;
  } else if (period === "daily") {
    return now - lastReset > dayMs;
  }
  return false;
}

// Format token count for display
function formatTokens(count: number): string {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  } else if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
}

// PKCE helpers
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

// Get user email from access token
async function getUserEmail(accessToken: string): Promise<string | undefined> {
  try {
    const response = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const data = (await response.json()) as { email?: string };
      return data.email;
    }
  } catch {
    // Ignore
  }
  return undefined;
}

// Discover or provision project for user
async function discoverProject(
  accessToken: string,
  onProgress?: (msg: string) => void
): Promise<string> {
  onProgress?.("Discovering project...");

  try {
    const response = await fetch(
      "https://daily-cloudcode-pa.sandbox.googleapis.com/v1/cloudcode/user:getSettings",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.ok) {
      const data = (await response.json()) as { projectId?: string };
      if (data.projectId) {
        return data.projectId;
      }
    }
  } catch {
    // Fall through
  }

  onProgress?.("Provisioning project...");
  try {
    const response = await fetch(
      "https://daily-cloudcode-pa.sandbox.googleapis.com/v1/cloudcode/user:provisionProject",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      }
    );
    if (response.ok) {
      const data = (await response.json()) as { projectId?: string };
      if (data.projectId) {
        return data.projectId;
      }
    }
  } catch {
    // Fall through
  }

  onProgress?.("Using default project...");
  return OAUTH_CONFIG.defaultProjectId;
}

// Refresh an access token
async function refreshAccessToken(
  refreshToken: string,
  projectId: string
): Promise<AntigravityCredentials> {
  const response = await fetch(OAUTH_CONFIG.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: OAUTH_CONFIG.clientId,
      client_secret: OAUTH_CONFIG.clientSecret,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token refresh failed: ${error}`);
  }

  const data = (await response.json()) as {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
  };

  return {
    type: "oauth",
    refresh: data.refresh_token || refreshToken,
    access: data.access_token,
    expires: Date.now() + data.expires_in * 1000 - 5 * 60 * 1000,
    projectId,
  };
}

// OAuth login flow with local callback server
async function performOAuthLogin(
  onUrl: (url: string) => void,
  onProgress: (msg: string) => void
): Promise<AntigravityCredentials> {
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);

  const authParams = new URLSearchParams({
    client_id: OAUTH_CONFIG.clientId,
    response_type: "code",
    redirect_uri: OAUTH_CONFIG.redirectUri,
    scope: OAUTH_CONFIG.scopes.join(" "),
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: verifier,
    access_type: "offline",
    prompt: "consent",
  });

  const authUrl = `${OAUTH_CONFIG.authUrl}?${authParams.toString()}`;

  return new Promise((resolve, reject) => {
    let resolved = false;

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url || "", `http://localhost:${OAUTH_CONFIG.redirectPort}`);

      if (url.pathname !== "/oauth-callback") {
        res.writeHead(404);
        res.end();
        return;
      }

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h1>Authentication Failed</h1><p>Error: ${error}</p></body></html>`);
        if (!resolved) {
          resolved = true;
          server.close();
          reject(new Error(`OAuth error: ${error}`));
        }
        return;
      }

      if (!code || !state || state !== verifier) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h1>Authentication Failed</h1><p>Invalid response.</p></body></html>`);
        if (!resolved) {
          resolved = true;
          server.close();
          reject(new Error("OAuth validation failed"));
        }
        return;
      }

      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`
        <html>
          <body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #1a1a2e; color: #eee;">
            <div style="text-align: center;">
              <h1 style="color: #4ade80;">✓ Authentication Successful</h1>
              <p>You can close this window and return to the terminal.</p>
            </div>
          </body>
        </html>
      `);

      if (resolved) return;
      resolved = true;
      server.close();

      try {
        onProgress("Exchanging authorization code for tokens...");

        const tokenResponse = await fetch(OAUTH_CONFIG.tokenUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: OAUTH_CONFIG.clientId,
            client_secret: OAUTH_CONFIG.clientSecret,
            code: code,
            grant_type: "authorization_code",
            redirect_uri: OAUTH_CONFIG.redirectUri,
            code_verifier: verifier,
          }),
        });

        if (!tokenResponse.ok) {
          throw new Error(`Token exchange failed: ${await tokenResponse.text()}`);
        }

        const tokens = (await tokenResponse.json()) as {
          access_token: string;
          refresh_token?: string;
          expires_in: number;
        };

        if (!tokens.refresh_token) {
          throw new Error("No refresh token received. Please try again.");
        }

        onProgress("Getting user info...");
        const email = await getUserEmail(tokens.access_token);
        const projectId = await discoverProject(tokens.access_token, onProgress);

        resolve({
          type: "oauth",
          refresh: tokens.refresh_token,
          access: tokens.access_token,
          expires: Date.now() + tokens.expires_in * 1000 - 5 * 60 * 1000,
          projectId,
          email,
        });
      } catch (err) {
        reject(err);
      }
    });

    server.on("error", (err) => {
      if (!resolved) {
        resolved = true;
        reject(new Error(`Failed to start OAuth server: ${err.message}`));
      }
    });

    server.listen(OAUTH_CONFIG.redirectPort, "127.0.0.1", () => {
      onUrl(authUrl);
    });

    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        server.close();
        reject(new Error("OAuth login timed out (5 minutes)"));
      }
    }, 5 * 60 * 1000);
  });
}

export default function (pi: ExtensionAPI) {
  let state = loadState();
  let lastSwitchTime = 0;
  const SWITCH_COOLDOWN = 3000;

  // Helper to check if text indicates a rate limit / quota error
  function isQuotaError(text: string): boolean {
    const lower = text.toLowerCase();
    return (
      lower.includes("rate limit") ||
      lower.includes("rate_limit") ||
      lower.includes("quota exceeded") ||
      lower.includes("resource exhausted") ||
      lower.includes("too many requests") ||
      lower.includes("insufficient_quota") ||
      lower.includes("429") ||
      lower.includes("503")
    );
  }

  // Check and reset tokens if needed based on reset period
  function checkAndResetTokens() {
    for (const account of state.accounts) {
      if (shouldResetTokens(account.tokenUsage.lastReset, state.config.resetPeriod)) {
        account.tokenUsage = createEmptyTokenUsage();
      }
    }
    saveState(state);
  }

  // Check if current account should be rotated based on token usage
  function shouldRotateAccount(): boolean {
    if (state.accounts.length <= 1) return false;
    
    const currentAccount = state.accounts[state.currentIndex];
    if (!currentAccount) return false;

    const config = state.config;
    
    if (config.strategy === "token") {
      return currentAccount.tokenUsage.total >= config.tokenThreshold;
    } else if (config.strategy === "request") {
      return currentAccount.tokenUsage.requestCount >= config.requestThreshold;
    }
    
    return false;
  }

  // Update token usage for current account
  function updateTokenUsage(inputTokens: number, outputTokens: number) {
    const currentAccount = state.accounts[state.currentIndex];
    if (!currentAccount) return;

    currentAccount.tokenUsage.input += inputTokens;
    currentAccount.tokenUsage.output += outputTokens;
    currentAccount.tokenUsage.total += inputTokens + outputTokens;
    currentAccount.tokenUsage.requestCount += 1;
    
    saveState(state);
  }

  // Get the next account with lowest token usage
  function getNextAccountIndex(): number {
    if (state.accounts.length <= 1) return 0;

    // Find account with lowest token usage
    let minIndex = 0;
    let minTokens = Infinity;

    for (let i = 0; i < state.accounts.length; i++) {
      if (i === state.currentIndex) continue; // Skip current
      
      const usage = state.accounts[i].tokenUsage.total;
      if (usage < minTokens) {
        minTokens = usage;
        minIndex = i;
      }
    }

    return minIndex;
  }

  async function switchToNext(ctx: ExtensionContext, reason?: string): Promise<boolean> {
    if (state.accounts.length <= 1) {
      ctx.ui.notify("❌ No other accounts available", "warning");
      return false;
    }

    const previousAccount = state.accounts[state.currentIndex];
    if (previousAccount) {
      previousAccount.lastUsed = Date.now();
    }

    // Use smart selection - pick account with lowest usage
    state.currentIndex = getNextAccountIndex();
    const account = state.accounts[state.currentIndex];

    try {
      if (account.credentials.expires < Date.now() + 60000) {
        const refreshed = await refreshAccessToken(
          account.credentials.refresh,
          account.credentials.projectId
        );
        account.credentials = refreshed;
      }
    } catch (e: any) {
      ctx.ui.notify(`⚠️ Token refresh failed for ${account.nickname}, trying next...`, "warning");
      // Mark this account and try another
      state.currentIndex = (state.currentIndex + 1) % state.accounts.length;
      return switchToNext(ctx, reason);
    }

    setAntigravityCredentials(account.credentials);
    saveState(state);
    lastSwitchTime = Date.now();

    const usage = account.tokenUsage;
    const msg = reason
      ? `${reason}\n\n🔄 Switched to: "${account.nickname}" (${formatTokens(usage.total)} tokens used)`
      : `🔄 Switched to: "${account.nickname}" (${formatTokens(usage.total)} tokens used)`;

    ctx.ui.notify(msg, "info");
    return true;
  }

  // Update status display with current account and usage
  function updateStatusDisplay(ctx: ExtensionContext) {
    if (state.accounts.length === 0) {
      ctx.ui.setStatus("antigravity", "");
      return;
    }

    const account = state.accounts[state.currentIndex];
    if (!account) return;

    const usage = account.tokenUsage;
    const threshold = state.config.tokenThreshold;
    const percent = Math.min(100, Math.round((usage.total / threshold) * 100));
    
    const status = `🔄 ${account.nickname}: ${formatTokens(usage.total)}/${formatTokens(threshold)} (${percent}%)`;
    ctx.ui.setStatus("antigravity", status);
  }

  // Restore current account on startup
  pi.on("session_start", async (_event, ctx) => {
    state = loadState();
    checkAndResetTokens();

    if (state.accounts.length > 0) {
      const account = state.accounts[state.currentIndex];
      if (account) {
        try {
          if (account.credentials.expires < Date.now() + 60000) {
            const refreshed = await refreshAccessToken(
              account.credentials.refresh,
              account.credentials.projectId
            );
            account.credentials = refreshed;
            saveState(state);
          }
          setAntigravityCredentials(account.credentials);
          
          const usage = account.tokenUsage;
          ctx.ui.notify(
            `🔄 Antigravity: ${account.nickname} (${state.currentIndex + 1}/${state.accounts.length})\n` +
            `   Tokens: ${formatTokens(usage.total)}/${formatTokens(state.config.tokenThreshold)}`,
            "info"
          );
          
          updateStatusDisplay(ctx);
        } catch (e: any) {
          ctx.ui.notify(`⚠️ Token refresh failed for ${account.nickname}: ${e.message}`, "warning");
        }
      }
    }
  });

  // Monitor token usage from responses
  pi.on("turn_end", async (event, ctx) => {
    const message = event.message;
    if (!message) return;

    // Extract token usage from the message
    const usage = message.usage;
    if (usage) {
      const inputTokens = usage.input || 0;
      const outputTokens = usage.output || 0;
      
      updateTokenUsage(inputTokens, outputTokens);
      updateStatusDisplay(ctx);

      // Check if we should rotate based on token threshold
      if (shouldRotateAccount() && Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
        const currentAccount = state.accounts[state.currentIndex];
        await switchToNext(
          ctx, 
          `📊 Token threshold reached for "${currentAccount.nickname}" (${formatTokens(currentAccount.tokenUsage.total)} tokens)`
        );
        updateStatusDisplay(ctx);
      }
    }

    // Also check for rate limit errors
    if (state.accounts.length > 1) {
      for (const block of message.content) {
        if (block.type === "text" && isQuotaError(block.text)) {
          if (Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
            await switchToNext(ctx, "⚠️ Rate limit detected");
            updateStatusDisplay(ctx);
          }
          return;
        }
      }

      if (message.stopReason === "error" && message.errorMessage && isQuotaError(message.errorMessage)) {
        if (Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
          await switchToNext(ctx, `⚠️ API Error: ${message.errorMessage.substring(0, 50)}`);
          updateStatusDisplay(ctx);
        }
      }
    }
  });

  // Monitor for errors at agent level
  pi.on("agent_end", async (event, ctx) => {
    if (state.accounts.length <= 1) return;
    
    for (const msg of event.messages || []) {
      if (msg.role === "assistant" && msg.stopReason === "error" && msg.errorMessage) {
        if (isQuotaError(msg.errorMessage) && Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
          await switchToNext(ctx, `⚠️ Error: ${msg.errorMessage.substring(0, 50)}`);
          updateStatusDisplay(ctx);
          return;
        }
      }
    }
  });

  // /antigravity:login
  pi.registerCommand("antigravity:login", {
    description: "Login to a new Antigravity account via OAuth",
    handler: async (_args, ctx) => {
      ctx.ui.notify("Starting OAuth login...\nA browser window will open.", "info");

      try {
        const credentials = await performOAuthLogin(
          (url) => {
            ctx.ui.notify(`\n🔐 Open this URL in your browser:\n\n${url}\n\nWaiting for login...`, "info");
            try {
              const { exec } = require("child_process");
              const cmd = process.platform === "win32"
                ? `start "" "${url}"`
                : process.platform === "darwin"
                  ? `open "${url}"`
                  : `xdg-open "${url}"`;
              exec(cmd);
            } catch { }
          },
          (msg) => ctx.ui.notify(msg, "info")
        );

        const suggestedName = credentials.email
          ? credentials.email.split("@")[0]
          : `Account ${state.accounts.length + 1}`;

        const nickname = await ctx.ui.input("Give this account a nickname:", suggestedName);
        if (!nickname) {
          ctx.ui.notify("Login cancelled", "warning");
          return;
        }

        const existingIdx = state.accounts.findIndex((a) => a.projectId === credentials.projectId);

        const entry: AccountEntry = {
          id: generateId(),
          projectId: credentials.projectId,
          credentials,
          addedAt: Date.now(),
          nickname,
          email: credentials.email,
          tokenUsage: createEmptyTokenUsage(),
        };

        if (existingIdx >= 0) {
          // Preserve token usage when updating
          entry.tokenUsage = state.accounts[existingIdx].tokenUsage;
          state.accounts[existingIdx] = entry;
          state.currentIndex = existingIdx;
          ctx.ui.notify(`✓ Updated: ${nickname}`, "success");
        } else {
          state.accounts.push(entry);
          state.currentIndex = state.accounts.length - 1;
          ctx.ui.notify(`✓ Added: ${nickname} (${state.accounts.length} total)`, "success");
        }

        setAntigravityCredentials(credentials);
        saveState(state);
        updateStatusDisplay(ctx);
      } catch (e: any) {
        ctx.ui.notify(`❌ Login failed: ${e.message}`, "error");
      }
    },
  });

  // /antigravity:list
  pi.registerCommand("antigravity:list", {
    description: "List all Antigravity accounts with token usage",
    handler: async (_args, ctx) => {
      state = loadState();
      checkAndResetTokens();

      if (state.accounts.length === 0) {
        ctx.ui.notify("No accounts. Use /antigravity:login to add one.", "info");
        return;
      }

      const threshold = state.config.tokenThreshold;
      const lines = state.accounts.map((a, i) => {
        const current = i === state.currentIndex ? "→ " : "  ";
        const expired = a.credentials.expires < Date.now() ? " ⚠️ expired" : "";
        const usage = a.tokenUsage;
        const percent = Math.min(100, Math.round((usage.total / threshold) * 100));
        const progressBar = createProgressBar(percent, 10);
        
        return `${current}${i + 1}. ${a.nickname}${expired}
     ${progressBar} ${formatTokens(usage.total)}/${formatTokens(threshold)} (${percent}%)
     Requests: ${usage.requestCount} | In: ${formatTokens(usage.input)} | Out: ${formatTokens(usage.output)}`;
      });

      ctx.ui.notify(
        `\n📋 Accounts (${state.accounts.length}) - Strategy: ${state.config.strategy}\n\n${lines.join("\n\n")}`,
        "info"
      );
    },
  });

  // /antigravity:usage
  pi.registerCommand("antigravity:usage", {
    description: "Show detailed token usage statistics",
    handler: async (_args, ctx) => {
      state = loadState();
      checkAndResetTokens();

      if (state.accounts.length === 0) {
        ctx.ui.notify("No accounts configured.", "info");
        return;
      }

      let totalTokens = 0;
      let totalRequests = 0;

      const lines = state.accounts.map((a, i) => {
        const usage = a.tokenUsage;
        totalTokens += usage.total;
        totalRequests += usage.requestCount;
        
        const current = i === state.currentIndex ? "→ " : "  ";
        const lastReset = new Date(usage.lastReset).toLocaleString();
        
        return `${current}${a.nickname}:
     Total: ${formatTokens(usage.total)} | Input: ${formatTokens(usage.input)} | Output: ${formatTokens(usage.output)}
     Requests: ${usage.requestCount} | Last Reset: ${lastReset}`;
      });

      const summary = `📊 Total Usage Summary
━━━━━━━━━━━━━━━━━━━━
Total Tokens: ${formatTokens(totalTokens)}
Total Requests: ${totalRequests}
Strategy: ${state.config.strategy}
Threshold: ${formatTokens(state.config.tokenThreshold)} tokens
Reset Period: ${state.config.resetPeriod}

📋 Per-Account Usage:
${lines.join("\n\n")}`;

      ctx.ui.notify(summary, "info");
    },
  });

  // /antigravity:config
  pi.registerCommand("antigravity:config", {
    description: "Configure round-robin settings",
    handler: async (_args, ctx) => {
      const options = [
        `Token Threshold: ${formatTokens(state.config.tokenThreshold)}`,
        `Reset Period: ${state.config.resetPeriod}`,
        `Strategy: ${state.config.strategy}`,
        "Reset to defaults",
      ];

      const choice = await ctx.ui.select("Configure:", options);
      if (!choice) return;

      if (choice.startsWith("Token Threshold")) {
        const input = await ctx.ui.input(
          "Token threshold (switch after N tokens):",
          state.config.tokenThreshold.toString()
        );
        if (input) {
          const value = parseInt(input, 10);
          if (!isNaN(value) && value > 0) {
            state.config.tokenThreshold = value;
            saveState(state);
            ctx.ui.notify(`✓ Token threshold set to ${formatTokens(value)}`, "success");
          } else {
            ctx.ui.notify("Invalid value", "error");
          }
        }
      } else if (choice.startsWith("Reset Period")) {
        const periods = ["hourly", "daily", "never"];
        const periodChoice = await ctx.ui.select("Reset counters:", periods);
        if (periodChoice) {
          state.config.resetPeriod = periodChoice as "hourly" | "daily" | "never";
          saveState(state);
          ctx.ui.notify(`✓ Reset period set to ${periodChoice}`, "success");
        }
      } else if (choice.startsWith("Strategy")) {
        const strategies = ["token", "request", "manual"];
        const strategyChoice = await ctx.ui.select("Round-robin strategy:", strategies);
        if (strategyChoice) {
          state.config.strategy = strategyChoice as "token" | "request" | "manual";
          saveState(state);
          ctx.ui.notify(`✓ Strategy set to ${strategyChoice}`, "success");
        }
      } else if (choice === "Reset to defaults") {
        state.config = { ...DEFAULT_CONFIG };
        saveState(state);
        ctx.ui.notify("✓ Configuration reset to defaults", "success");
      }

      updateStatusDisplay(ctx);
    },
  });

  // /antigravity:reset
  pi.registerCommand("antigravity:reset", {
    description: "Reset token counters for all accounts",
    handler: async (_args, ctx) => {
      if (state.accounts.length === 0) {
        ctx.ui.notify("No accounts to reset.", "info");
        return;
      }

      const confirmed = await ctx.ui.confirm(
        "Reset token counters?",
        "This will reset usage stats for all accounts."
      );
      if (!confirmed) return;

      for (const account of state.accounts) {
        account.tokenUsage = createEmptyTokenUsage();
      }
      saveState(state);
      updateStatusDisplay(ctx);

      ctx.ui.notify("✓ Token counters reset for all accounts", "success");
    },
  });

  // /antigravity:switch
  pi.registerCommand("antigravity:switch", {
    description: "Switch to a different account",
    handler: async (_args, ctx) => {
      if (state.accounts.length <= 1) {
        ctx.ui.notify(
          state.accounts.length === 0 ? "No accounts. Use /antigravity:login" : "Only one account configured",
          "info"
        );
        return;
      }

      const threshold = state.config.tokenThreshold;
      const options = state.accounts.map((a, i) => {
        const current = i === state.currentIndex ? " ← current" : "";
        const percent = Math.min(100, Math.round((a.tokenUsage.total / threshold) * 100));
        return `${a.nickname} (${percent}% used)${current}`;
      });

      const choice = await ctx.ui.select("Switch to:", options);
      if (!choice) return;

      const idx = options.findIndex((o) => o === choice);
      if (idx < 0 || idx === state.currentIndex) return;

      state.accounts[state.currentIndex].lastUsed = Date.now();
      state.currentIndex = idx;
      const account = state.accounts[idx];

      try {
        if (account.credentials.expires < Date.now() + 60000) {
          const refreshed = await refreshAccessToken(
            account.credentials.refresh,
            account.credentials.projectId
          );
          account.credentials = refreshed;
        }
        setAntigravityCredentials(account.credentials);
        saveState(state);
        updateStatusDisplay(ctx);
        ctx.ui.notify(`✓ Switched to: ${account.nickname}`, "success");
      } catch (e: any) {
        ctx.ui.notify(`❌ Failed: ${e.message}`, "error");
      }
    },
  });

  // /antigravity:remove
  pi.registerCommand("antigravity:remove", {
    description: "Remove an account",
    handler: async (_args, ctx) => {
      if (state.accounts.length === 0) {
        ctx.ui.notify("No accounts to remove.", "info");
        return;
      }

      const options = state.accounts.map((a, i) => {
        const current = i === state.currentIndex ? " ← current" : "";
        return `${a.nickname}${current}`;
      });

      const choice = await ctx.ui.select("Remove:", options);
      if (!choice) return;

      const idx = options.findIndex((o) => o === choice);
      if (idx < 0) return;

      const confirmed = await ctx.ui.confirm("Remove?", `Remove "${state.accounts[idx].nickname}"?`);
      if (!confirmed) return;

      const removed = state.accounts.splice(idx, 1)[0];

      if (state.accounts.length === 0) {
        state.currentIndex = 0;
        const auth = loadAuthJson();
        delete auth["google-antigravity"];
        saveAuthJson(auth);
      } else {
        if (state.currentIndex >= state.accounts.length) {
          state.currentIndex = state.accounts.length - 1;
        }
        setAntigravityCredentials(state.accounts[state.currentIndex].credentials);
      }

      saveState(state);
      updateStatusDisplay(ctx);
      ctx.ui.notify(`✓ Removed: ${removed.nickname}`, "success");
    },
  });

  // /antigravity:clear
  pi.registerCommand("antigravity:clear", {
    description: "Clear all accounts",
    handler: async (_args, ctx) => {
      if (state.accounts.length === 0) {
        ctx.ui.notify("No accounts to clear.", "info");
        return;
      }

      const confirmed = await ctx.ui.confirm("Clear all?", `Remove all ${state.accounts.length} account(s)?`);
      if (!confirmed) return;

      state = {
        accounts: [],
        currentIndex: 0,
        config: state.config, // Preserve config
        lastConfigUpdate: Date.now(),
      };
      saveState(state);

      const auth = loadAuthJson();
      delete auth["google-antigravity"];
      saveAuthJson(auth);

      updateStatusDisplay(ctx);
      ctx.ui.notify("✓ All accounts cleared", "success");
    },
  });

  // Ctrl+Shift+A - quick switch
  pi.registerShortcut("ctrl+shift+a", {
    description: "Switch to next Antigravity account",
    handler: async (ctx) => {
      if (state.accounts.length <= 1) {
        ctx.ui.notify(state.accounts.length === 0 ? "No accounts" : "Only one account", "warning");
        return;
      }
      await switchToNext(ctx, "Quick switch");
      updateStatusDisplay(ctx);
    },
  });
}

// Helper to create a progress bar
function createProgressBar(percent: number, width: number): string {
  const filled = Math.round((percent / 100) * width);
  const empty = width - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);
  return `[${bar}]`;
}
