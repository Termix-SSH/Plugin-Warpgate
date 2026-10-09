import type {
  PluginKeyboardInteractiveDetection,
  PluginKeyboardInteractivePrompt,
} from "@termix-ssh/plugin-sdk/backend";

const WARPGATE_PATTERN = /warpgate\s+authentication/i;
const URL_PATTERN = /https?:\/\/[^\s\n]+/i;
const SECURITY_KEY_PATTERN =
  /security key[:\s]+([a-z0-9](?:\s+[a-z0-9]){3}|[a-z0-9]{4})/i;

/**
 * Warpgate asks for its browser approval as a keyboard-interactive round
 * that names itself and carries the sign-in URL and a security key.
 */
export function detectWarpgateRound(round: {
  name: string;
  instructions: string;
  prompts: PluginKeyboardInteractivePrompt[];
}): PluginKeyboardInteractiveDetection | null {
  const texts = round.prompts.map((prompt) => prompt.prompt);
  const isWarpgate =
    WARPGATE_PATTERN.test(round.name) ||
    WARPGATE_PATTERN.test(round.instructions) ||
    texts.some((text) => WARPGATE_PATTERN.test(text));
  if (!isWarpgate) return null;

  const fullText = `${round.name}\n${round.instructions}\n${texts.join("\n")}`;
  const url = fullText.match(URL_PATTERN);
  if (!url) return null;
  const key = fullText.match(SECURITY_KEY_PATTERN);
  return {
    kind: "browser",
    // A sentence can end right after the link.
    url: url[0].replace(/[.,;:!?)\]]+$/, ""),
    code: key ? key[1] : "N/A",
    instructions: round.instructions,
  };
}
