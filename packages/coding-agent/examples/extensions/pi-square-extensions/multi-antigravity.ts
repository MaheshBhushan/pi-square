/**
 * Multi-Account Antigravity Extension
 *
 * Manages multiple Google Antigravity accounts and automatically switches
 * between them when rate limits or quota errors are detected.
 *
 * SETUP:
 * 1. Run `/antigravity:login` to add your first account
 * 2. Complete the OAuth flow in your browser
 * 3. Repeat for additional accounts
 *
 * COMMANDS:
 * - /antigravity:login   - Login to a new Antigravity account (OAuth)
 * - /antigravity:list    - List all saved accounts
 * - /antigravity:switch  - Switch to a different account
 * - /antigravity:remove  - Remove an account
 * - /antigravity:clear   - Clear all accounts
 *
 * KEYBOARD:
 * - Ctrl+Shift+A - Quick switch to next account
 *
 * AUTO-SWITCH:
 * The extension monitors for rate limit errors (429, quota exceeded, etc.)
 * and automatically switches to the next available account.
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

interface AccountEntry {
  id: string;
  projectId: string;
  credentials: AntigravityCredentials;
  addedAt: number;
  lastUsed?: number;
  nickname: string;
  email?: string;
}

interface MultiAccountState {
  accounts: AccountEntry[];
  currentIndex: number;
}

const PI_DIR = path.join(os.homedir(), ".pi", "agent");
const AUTH_FILE = path.join(PI_DIR, "auth.json");
const STATE_FILE = path.join(PI_DIR, "multi-antigravity-state.json");

// Antigravity OAuth config - matches Pi's internal config
// These are Google's public OAuth client credentials for CLI apps
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

function loadState(): MultiAccountState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, "utf-8"));
    }
  } catch (e) {
    // Ignore
  }
  return { accounts: [], currentIndex: 0 };
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

  // Try to get existing project
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
    // Fall through to provision
  }

  // Try to provision a new project
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
    // Fall through to default
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

  // Build auth URL
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

  // Start local server to capture callback
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
        res.end(`<html><body><h1>Authentication Failed</h1><p>Error: ${error}</p><p>You can close this window.</p></body></html>`);
        if (!resolved) {
          resolved = true;
          server.close();
          reject(new Error(`OAuth error: ${error}`));
        }
        return;
      }

      if (!code || !state) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h1>Authentication Failed</h1><p>Missing code or state parameter.</p></body></html>`);
        return;
      }

      if (state !== verifier) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h1>Authentication Failed</h1><p>State mismatch - possible CSRF attack.</p></body></html>`);
        if (!resolved) {
          resolved = true;
          server.close();
          reject(new Error("OAuth state mismatch"));
        }
        return;
      }

      // Success page
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

        // Exchange code for tokens
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
          const errorText = await tokenResponse.text();
          throw new Error(`Token exchange failed: ${errorText}`);
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
        reject(new Error(`Failed to start OAuth server on port ${OAUTH_CONFIG.redirectPort}: ${err.message}`));
      }
    });

    server.listen(OAUTH_CONFIG.redirectPort, "127.0.0.1", () => {
      onUrl(authUrl);
    });

    // Timeout after 5 minutes
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
  const SWITCH_COOLDOWN = 5000;

  // Helper to check if text indicates a rate limit / quota error
  function isQuotaError(text: string): boolean {
    const lower = text.toLowerCase();
    return (
      lower.includes("rate limit") ||
      lower.includes("rate_limit") ||
      lower.includes("ratelimit") ||
      lower.includes("quota exceeded") ||
      lower.includes("quota_exceeded") ||
      lower.includes("resource exhausted") ||
      lower.includes("resource_exhausted") ||
      lower.includes("too many requests") ||
      lower.includes("insufficient_quota") ||
      lower.includes("insufficient quota") ||
      lower.includes("limit exceeded") ||
      lower.includes("daily limit") ||
      lower.includes("usage limit") ||
      lower.includes("tokens exceeded") ||
      lower.includes("capacity") ||
      lower.includes("overloaded") ||
      lower.includes("429") ||
      lower.includes("503")
    );
  }

  // Restore current account on startup
  pi.on("session_start", async (_event, ctx) => {
    state = loadState();

    if (state.accounts.length > 0) {
      const account = state.accounts[state.currentIndex];
      if (account) {
        try {
          // Refresh if expired
          if (account.credentials.expires < Date.now() + 60000) {
            const refreshed = await refreshAccessToken(
              account.credentials.refresh,
              account.credentials.projectId
            );
            account.credentials = refreshed;
            saveState(state);
          }
          setAntigravityCredentials(account.credentials);
          ctx.ui.notify(
            `🔄 Antigravity: ${account.nickname} (${state.currentIndex + 1}/${state.accounts.length})`,
            "info"
          );
        } catch (e: any) {
          ctx.ui.notify(`⚠️ Token refresh failed for ${account.nickname}: ${e.message}`, "warning");
        }
      }
    }
  });

  // Monitor for rate limit errors in responses
  pi.on("turn_end", async (event, ctx) => {
    if (state.accounts.length <= 1) return;
    const message = event.message;
    if (!message) return;

    // Check message content
    for (const block of message.content) {
      if (block.type === "text" && isQuotaError(block.text)) {
        if (Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
          await switchToNext(ctx, "⚠️ Rate limit detected in response");
        }
        return;
      }
    }

    // Check if message has error stop reason
    if (message.stopReason === "error" && message.errorMessage) {
      if (isQuotaError(message.errorMessage)) {
        if (Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
          await switchToNext(ctx, `⚠️ API Error: ${message.errorMessage.substring(0, 50)}`);
        }
      }
    }
  });

  // Monitor for errors at agent level
  pi.on("agent_end", async (event, ctx) => {
    if (state.accounts.length <= 1) return;
    for (const msg of event.messages || []) {
      if (msg.role === "assistant" && msg.stopReason === "error" && msg.errorMessage) {
        if (isQuotaError(msg.errorMessage)) {
          if (Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
            await switchToNext(ctx, `⚠️ Error: ${msg.errorMessage.substring(0, 50)}`);
          }
          return;
        }
      }
    }
  });

  // Also monitor tool results for API errors
  pi.on("tool_result", async (event, ctx) => {
    if (state.accounts.length <= 1) return;
    if (!event.isError) return;

    // Check tool result content for quota errors
    for (const block of event.content || []) {
      if (block.type === "text" && isQuotaError(block.text)) {
        if (Date.now() - lastSwitchTime > SWITCH_COOLDOWN) {
          await switchToNext(ctx, "⚠️ Quota error in tool execution");
        }
        return;
      }
    }
  });

  async function switchToNext(ctx: ExtensionContext, reason?: string): Promise<boolean> {
    if (state.accounts.length <= 1) {
      ctx.ui.notify("❌ No other accounts available to switch to", "warning");
      return false;
    }

    const previousAccount = state.accounts[state.currentIndex];
    if (previousAccount) {
      previousAccount.lastUsed = Date.now();
    }

    state.currentIndex = (state.currentIndex + 1) % state.accounts.length;
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
      return switchToNext(ctx, reason);
    }

    setAntigravityCredentials(account.credentials);
    saveState(state);
    lastSwitchTime = Date.now();

    // Clear, prominent notification
    const msg = reason
      ? `${reason}\n\n🔄 Switching to: "${account.nickname}"`
      : `🔄 Switching to: "${account.nickname}"`;

    ctx.ui.notify(msg, "warning");
    return true;
  }

  // /antigravity:login - OAuth login
  pi.registerCommand("antigravity:login", {
    description: "Login to a new Antigravity account via OAuth",
    handler: async (_args, ctx) => {
      ctx.ui.notify("Starting OAuth login...\nA browser window will open.", "info");

      try {
        const credentials = await performOAuthLogin(
          (url) => {
            ctx.ui.notify(
              `\n🔐 Open this URL in your browser:\n\n${url}\n\nWaiting for login...`,
              "info"
            );
            // Try to open browser automatically
            try {
              const { exec } = require("child_process");
              const cmd =
                process.platform === "win32"
                  ? `start "" "${url}"`
                  : process.platform === "darwin"
                    ? `open "${url}"`
                    : `xdg-open "${url}"`;
              exec(cmd);
            } catch {
              // Ignore - user can open manually
            }
          },
          (msg) => ctx.ui.notify(msg, "info")
        );

        // Suggest nickname based on email
        const suggestedName = credentials.email
          ? credentials.email.split("@")[0]
          : `Account ${state.accounts.length + 1}`;

        const nickname = await ctx.ui.input("Give this account a nickname:", suggestedName);

        if (!nickname) {
          ctx.ui.notify("Login cancelled", "warning");
          return;
        }

        // Check for existing
        const existingIdx = state.accounts.findIndex((a) => a.projectId === credentials.projectId);

        const entry: AccountEntry = {
          id: generateId(),
          projectId: credentials.projectId,
          credentials,
          addedAt: Date.now(),
          nickname,
          email: credentials.email,
        };

        if (existingIdx >= 0) {
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
      } catch (e: any) {
        ctx.ui.notify(`❌ Login failed: ${e.message}`, "error");
      }
    },
  });

  // /antigravity:list
  pi.registerCommand("antigravity:list", {
    description: "List all Antigravity accounts",
    handler: async (_args, ctx) => {
      // Always reload from disk to catch external changes
      state = loadState();

      if (state.accounts.length === 0) {
        ctx.ui.notify("No accounts. Use /antigravity:login to add one.", "info");
        return;
      }

      const lines = state.accounts.map((a, i) => {
        const current = i === state.currentIndex ? "→ " : "  ";
        const expired = a.credentials.expires < Date.now() ? " ⚠️ expired" : "";
        const email = a.email ? `\n     Email: ${a.email}` : "";
        return `${current}${i + 1}. ${a.nickname}${expired}${email}\n     Project: ${a.projectId}`;
      });

      ctx.ui.notify(`\n📋 Accounts (${state.accounts.length}):\n\n${lines.join("\n\n")}`, "info");
    },
  });

  // /antigravity:switch
  pi.registerCommand("antigravity:switch", {
    description: "Switch to a different account",
    handler: async (_args, ctx) => {
      if (state.accounts.length <= 1) {
        ctx.ui.notify(
          state.accounts.length === 0
            ? "No accounts. Use /antigravity:login"
            : "Only one account configured",
          "info"
        );
        return;
      }

      const options = state.accounts.map((a, i) => {
        const current = i === state.currentIndex ? " ← current" : "";
        return `${a.nickname}${current}`;
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

      state = { accounts: [], currentIndex: 0 };
      saveState(state);

      const auth = loadAuthJson();
      delete auth["google-antigravity"];
      saveAuthJson(auth);

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
    },
  });
}
