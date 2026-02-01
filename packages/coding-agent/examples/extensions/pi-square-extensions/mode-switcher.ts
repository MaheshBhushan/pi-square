/**
 * Mode Switcher Extension
 *
 * Switch between different operational modes:
 * - plan: Agent planning mode (read-only, structured reasoning)
 * - build: Normal coding mode (read + write)
 * - readonly: Read-only analysis mode
 *
 * COMMANDS:
 * - /mode:plan     - Switch to planning mode
 * - /mode:build    - Switch to build/coding mode
 * - /mode:readonly - Switch to read-only mode
 * - /mode          - Show current mode
 *
 * KEYBOARD:
 * - Ctrl+Shift+M   - Cycle through modes
 *
 * State is persisted to ~/.pi/agent/mode-switcher-state.json
 */

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

type Mode = "plan" | "build" | "readonly";

interface ModeConfig {
  name: string;
  label: string;
  emoji: string;
  color: string;
  tools: string[];
  systemPrompt?: string;
}

interface ModeState {
  currentMode: Mode;
  lastUpdated: number;
}

// State file path
const PI_DIR = path.join(os.homedir(), ".pi", "agent");
const STATE_FILE = path.join(PI_DIR, "mode-switcher-state.json");

// Default mode
const DEFAULT_MODE: Mode = "build";

const PLAN_MODE_PROMPT = `{
  "task": "run in agent mode",
  "topic": "autonomous task execution and problem solving",
  "audience": "ai system acting as an agent",
  "output_format": "step-by-step reasoning, actions, and final result",
  "instructions": [
    "act as an autonomous agent, not just a chatbot",
    "break the task into clear sub-tasks before starting",
    "decide what information or tools are needed for each step",
    "ask only essential clarification questions if required",
    "execute tasks sequentially and logically",
    "track progress and avoid repeating steps",
    "optimize for correctness, efficiency, and simplicity",
    "explain decisions briefly and clearly",
    "produce a final structured output with conclusions and next steps"
  ]
}

IMPORTANT: You are now in PLAN MODE (READ-ONLY).
- You can READ files and analyze code
- You CANNOT write, edit, or execute destructive commands
- Create a detailed plan with numbered steps
- Explain what changes WOULD be made, but don't execute them
- When the user is satisfied with the plan, they can switch to BUILD mode to execute
`;

const READONLY_PROMPT = `You are in READ-ONLY mode. You can analyze, review, and explain code, but you CANNOT:
- Write new files
- Edit existing files
- Execute commands that modify the filesystem

Focus on: analysis, code review, explanations, and recommendations.
If the user asks you to make changes, explain what changes you WOULD make but don't execute them.
`;

const MODES: Record<Mode, ModeConfig> = {
  plan: {
    name: "plan",
    label: "PLAN",
    emoji: "📋",
    color: "warning", // yellow
    tools: ["read", "grep", "find", "ls"], // READ-ONLY tools
    systemPrompt: PLAN_MODE_PROMPT,
  },
  build: {
    name: "build",
    label: "BUILD",
    emoji: "🔨",
    color: "success", // green
    tools: ["read", "bash", "edit", "write", "grep", "find", "ls"],
  },
  readonly: {
    name: "readonly",
    label: "READ-ONLY",
    emoji: "👁️",
    color: "accent", // blue
    tools: ["read", "grep", "find", "ls"],
    systemPrompt: READONLY_PROMPT,
  },
};

const MODE_ORDER: Mode[] = ["build", "plan", "readonly"];

// State management functions
function loadState(): ModeState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const data = JSON.parse(fs.readFileSync(STATE_FILE, "utf-8"));
      // Validate mode exists
      if (data.currentMode && MODES[data.currentMode as Mode]) {
        return data as ModeState;
      }
    }
  } catch (e) {
    // Ignore errors, return default
  }
  return { currentMode: DEFAULT_MODE, lastUpdated: Date.now() };
}

function saveState(state: ModeState): void {
  try {
    // Ensure directory exists
    if (!fs.existsSync(PI_DIR)) {
      fs.mkdirSync(PI_DIR, { recursive: true });
    }
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch (e) {
    // Ignore write errors
  }
}

export default function (pi: ExtensionAPI) {
  // Load persisted state
  let state = loadState();

  function updateModeDisplay(ctx: ExtensionContext) {
    const mode = MODES[state.currentMode];
    const indicator = `${mode.emoji} Mode: ${mode.label}`;

    // Show mode below the editor
    ctx.ui.setWidget(
      "mode-indicator",
      (tui, theme) => {
        const { Text } = require("@mariozechner/pi-tui");
        const colorFn = theme.fg.bind(theme);
        const styled = colorFn(mode.color as any, `  ${indicator}  `);
        return new Text(styled, 0, 0);
      },
      { placement: "belowEditor" }
    );

    // Also show in status bar
    ctx.ui.setStatus("mode", `${mode.emoji} ${mode.label}`);
  }

  function applyMode(ctx: ExtensionContext, notify = true) {
    const mode = MODES[state.currentMode];

    // Set active tools based on mode
    pi.setActiveTools(mode.tools);

    // Update display
    updateModeDisplay(ctx);

    // Save state
    state.lastUpdated = Date.now();
    saveState(state);

    if (notify) {
      ctx.ui.notify(`${mode.emoji} Switched to ${mode.label} mode`, "info");
    }
  }

  function setMode(mode: Mode, ctx: ExtensionContext, notify = true) {
    // Reload state from disk first to avoid conflicts
    const diskState = loadState();

    // Update mode
    state = {
      currentMode: mode,
      lastUpdated: Date.now(),
    };

    applyMode(ctx, notify);
  }

  // Initialize on session start
  pi.on("session_start", async (_event, ctx) => {
    // Reload state from disk (in case it was changed externally)
    state = loadState();
    applyMode(ctx, false);
  });

  // Inject system prompt based on mode
  pi.on("before_agent_start", async (event, ctx) => {
    // Reload state to catch any external changes
    state = loadState();
    const mode = MODES[state.currentMode];

    // Update tools in case mode changed externally
    pi.setActiveTools(mode.tools);
    updateModeDisplay(ctx);

    if (mode.systemPrompt) {
      return {
        systemPrompt: event.systemPrompt + "\n\n" + mode.systemPrompt,
      };
    }
    return {};
  });

  // /mode - show current mode
  pi.registerCommand("mode", {
    description: "Show current mode",
    handler: async (_args, ctx) => {
      // Reload from disk
      state = loadState();
      const mode = MODES[state.currentMode];
      const toolsList = mode.tools.join(", ");
      ctx.ui.notify(
        `${mode.emoji} Current mode: ${mode.label}\n\nTools: ${toolsList}\n\nUse /mode:plan, /mode:build, or /mode:readonly to switch`,
        "info"
      );
    },
  });

  // /mode:plan
  pi.registerCommand("mode:plan", {
    description: "Switch to planning mode (read-only, structured reasoning)",
    handler: async (_args, ctx) => {
      setMode("plan", ctx);
    },
  });

  // /mode:build
  pi.registerCommand("mode:build", {
    description: "Switch to build mode (full read/write access)",
    handler: async (_args, ctx) => {
      setMode("build", ctx);
    },
  });

  // /mode:readonly
  pi.registerCommand("mode:readonly", {
    description: "Switch to read-only mode (analysis only)",
    handler: async (_args, ctx) => {
      setMode("readonly", ctx);
    },
  });

  // Ctrl+Shift+M - cycle modes
  pi.registerShortcut("ctrl+shift+m", {
    description: "Cycle through modes (build → plan → readonly)",
    handler: async (ctx) => {
      // Reload state first
      state = loadState();

      const currentIndex = MODE_ORDER.indexOf(state.currentMode);
      const nextIndex = (currentIndex + 1) % MODE_ORDER.length;
      setMode(MODE_ORDER[nextIndex], ctx);
    },
  });
}
