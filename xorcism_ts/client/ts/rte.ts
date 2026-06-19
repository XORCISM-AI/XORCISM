/**
 * rte.ts — Shared rich-text editor (WYSIWYG).
 *
 * Toolbar: bold, italic, underline, strikethrough, bullet list,
 * text color, highlight, clear formatting.
 *
 * The produced HTML is synchronized into a hidden <textarea>, so that any
 * code reading `.value` (collectRow, getElementById(...).value, etc.) receives
 * directly the formatted HTML to be saved in the database.
 */

import { t } from "./i18n";

export interface RichText {
  hidden: HTMLTextAreaElement; // carries the HTML value (.value)
  mount: HTMLElement; // visual element (toolbar + editable zone)
}

export function mkRichText(val?: string, placeholder?: string, opts?: { minHeight?: number }): RichText {
  const wrap = document.createElement("div");
  wrap.className = "rte-wrap";

  const toolbar = document.createElement("div");
  toolbar.className = "rte-toolbar";

  const editor = document.createElement("div");
  editor.className = "rte-editor";
  editor.contentEditable = "true";
  editor.dataset.placeholder = placeholder ?? "";
  editor.innerHTML = val ?? "";
  // Tall editor for long bodies (e.g. a full policy document) — overrides the
  // default min-height; the zone still grows with content and scrolls past it.
  if (opts?.minHeight) {
    editor.style.minHeight = `${opts.minHeight}px`;
    editor.style.maxHeight = "60vh";
    editor.style.overflowY = "auto";
    editor.style.resize = "vertical";
  }

  const hidden = document.createElement("textarea");
  hidden.style.display = "none";
  hidden.value = val ?? "";

  const sync = () => { hidden.value = editor.innerHTML; };
  editor.addEventListener("input", sync);
  editor.addEventListener("blur", sync);

  const exec = (cmd: string, arg?: string) => {
    editor.focus();
    // styleWithCSS produces <span style> (reliable color/highlight)
    try { document.execCommand("styleWithCSS", false, "true"); } catch { /* ignore */ }
    document.execCommand(cmd, false, arg);
    sync();
  };

  const mkBtn = (label: string, title: string, onClick: () => void): HTMLButtonElement => {
    const b = document.createElement("button");
    b.type = "button";
    b.title = title;
    b.innerHTML = label;
    // mousedown instead of click: avoids losing the selection in the editor
    b.addEventListener("mousedown", (ev) => { ev.preventDefault(); onClick(); });
    return b;
  };

  toolbar.appendChild(mkBtn("<b>B</b>", "Gras (Ctrl+B)", () => exec("bold")));
  toolbar.appendChild(mkBtn("<i>I</i>", "Italique (Ctrl+I)", () => exec("italic")));
  toolbar.appendChild(mkBtn("<u>U</u>", "Souligné (Ctrl+U)", () => exec("underline")));
  toolbar.appendChild(mkBtn("<s>S</s>", "Barré", () => exec("strikeThrough")));
  toolbar.appendChild(mkBtn("&bull;", "Liste à puces", () => exec("insertUnorderedList")));

  // Text color
  const color = document.createElement("input");
  color.type = "color";
  color.title = t("tip.textColor");
  color.value = "var(--accent)";
  color.addEventListener("mousedown", (ev) => ev.stopPropagation());
  color.addEventListener("input", () => exec("foreColor", color.value));
  toolbar.appendChild(color);

  // Highlight
  const hilite = document.createElement("input");
  hilite.type = "color";
  hilite.title = "Surlignage";
  hilite.value = "#fde047";
  hilite.addEventListener("mousedown", (ev) => ev.stopPropagation());
  hilite.addEventListener("input", () => exec("hiliteColor", hilite.value));
  toolbar.appendChild(hilite);

  toolbar.appendChild(mkBtn("&#10006;", "Effacer la mise en forme", () => exec("removeFormat")));

  wrap.appendChild(toolbar);
  wrap.appendChild(editor);
  return { hidden, mount: wrap };
}

/** Columns to edit as rich text (WYSIWYG). */
export function isRichTextCol(name: string): boolean {
  const n = name.toLowerCase();
  // Any *Description column (AssetDescription, ToolDescription, VULDescription…)
  return n.endsWith("description");
}
