import { afterEach, describe, expect, it } from "vitest";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

describe(`${manifest.id} activate`, () => {
  it("activates without registering any UI of its own", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toEqual([]);
    expect(rendered.registered.railItems()).toEqual([]);
    expect(rendered.registered.hostEditorSections()).toEqual([]);
    expect(rendered.shellCalls).toEqual([]);
  });
});
