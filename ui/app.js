const invoke = window.__TAURI__?.core?.invoke;
const listen = window.__TAURI__?.event?.listen;

const LANGUAGE_KEY = "vps-studio-language";
const storedLanguage = window.localStorage?.getItem(LANGUAGE_KEY);

// t("Opened {0}", name): translate, then fill {0}, {1}... placeholders.
function t(key, ...args) {
  const text = i18n[state.language]?.[key] ?? key;
  return args.length ? text.replace(/\{(\d+)\}/g, (match, index) => (index < args.length ? String(args[index] ?? "") : match)) : text;
}

const state = {
  language: LANGUAGES.some((lang) => lang.code === storedLanguage) ? storedLanguage : "zh",
  hosts: [],
  selectedHostId: null,
  selectedGroup: null,
  openedGroup: null,
  search: "",
  status: "Ready",
  view: "dashboard",
  section: "hosts",
  activeHost: null,
  activeShellId: null,
  sessionKind: null,
  shellHealthy: false,
  terminalFocused: false,
  connection: null,
  metrics: null,
  remotePath: "/root",
  remoteEntries: [],
  sftpSelected: [],
  sftpAnchor: null,
  terminal: "",
  term: null,
  commandInput: "",
  watchedFiles: [],
  editorOpen: false,
  editingHost: null,
  editingIndex: -1,
  detailOpen: false,
  detailKind: null,
  groupProfiles: {},
  editingGroup: null,
  keys: [],
  selectedKeyId: null,
  editingKey: null,
  editingKeyIndex: -1,
  identities: [],
  selectedIdentityId: null,
  editingIdentity: null,
  editingIdentityIndex: -1,
  keyGenerator: null,
  keyGenerating: false,
  snippets: [],
  selectedSnippetId: null,
  editingSnippet: null,
  editingSnippetIndex: -1,
  snippetPackages: [],
  selectedPackageId: null,
  openedPackageId: null,
  editingPackage: null,
  cmdCategory: "",
  cmdSelectedSnippetId: null,
  cmdEditorText: "",
  cmdOptions: { ctrlEnter: false, clearAfterSend: true, appendCr: true },
  cmdOptionsOpen: false,
  shellHistory: [],
  shellHistorySavingIndex: -1,
  sftpFilter: "",
  bottomTab: "files",
  hostMenuOpen: false,
  keyMenuOpen: false,
  languageMenuOpen: false,
  hostIdentityMenuOpen: false,
  sortMenuOpen: false,
  sortMode: "newest",
  showSearch: false,
  contextMenu: null,
  deleteDialog: null,
  logs: [],
  knownHosts: [],
};

function currentLocale() {
  return LANGUAGES.find((lang) => lang.code === state.language)?.locale || "en-US";
}

function toggleLanguage(lang) {
  // Status text is translated when it is set; re-translate the idle "Ready" text.
  const idle = LANGUAGES.some((item) => (i18n[item.code]?.Ready ?? "Ready") === state.status);
  state.language = lang;
  if (idle) state.status = t("Ready");
  document.documentElement.lang = currentLocale();
  window.localStorage?.setItem(LANGUAGE_KEY, lang);
  state.languageMenuOpen = false;
  render();
}

function handleGlobalClick(e) {
  if (state.hostMenuOpen || state.keyMenuOpen || state.snippetMenuOpen || state.hostIdentityMenuOpen || state.sortMenuOpen || state.contextMenu || state.languageMenuOpen) {
    closeMenus();
    render();
  }
  if (state.showSearch && !e.target.closest(".local-search-box") && !e.target.closest("[data-action='toggle-search']")) {
    state.showSearch = false;
    state.search = "";
    render();
  }
}

const app = document.querySelector("#app");
let deleteDialogResolver = null;
let terminalEventsRegistered = false;
let shellOutputPoller = null;
let shellOutputPolling = false;
let shellReconnecting = false;
let xterm = null;
let xtermFit = null;
let xtermDataDisposable = null;
let xtermResizeObserver = null;
let cardClickTimer = null;
const GROUP_PROFILES_KEY = "vps-studio.groupProfiles.v1";
const KEYCHAIN_KEY = "vps-studio.keychain.v1";
const IDENTITIES_KEY = "vps-studio.identities.v1";
const SNIPPETS_KEY = "vps-studio.snippets.v1";
const SHELL_HISTORY_KEY = "vps-studio.shellHistory.v1";
const LOGS_KEY = "vps-studio.logs.v1";

function emptyHost() {
  return {
    id: `host-${Date.now()}`,
    name: "",
    group: "",
    host: "",
    port: "",
    username: "",
    auth: { kind: "password", password: "" },
    defaultPath: "/root",
    snippets: [
      { name: "System update", command: "apt update && apt upgrade -y" },
      { name: "Disk usage", command: "df -h" },
      {
        name: "Top processes",
        command: "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head",
      },
    ],
  };
}

function emptyIdentity() {
  return {
    id: `ident-${Date.now()}`,
    label: "",
    username: "",
    auth: { kind: "password", password: "" },
  };
}

function ensureHost(host) {
  return {
    ...emptyHost(),
    ...host,
    id: host.id || `host-${Date.now()}`,
    port: host.port !== undefined && host.port !== "" ? Number(host.port) : "",
    defaultPath: host.defaultPath || host.default_path || "/root",
    auth: normalizeAuth(host.auth),
    snippets:
      Array.isArray(host.snippets) && host.snippets.length
        ? host.snippets
        : emptyHost().snippets,
  };
}

function normalizeAuth(auth) {
  if (!auth) return { kind: "password", password: "" };
  if (auth.kind) {
    if (auth.kind === "password") return { kind: "password", password: auth.password || "" };
    if (auth.kind === "keyRef") {
      return {
        kind: "keyRef",
        keyId: auth.keyId || auth.key_id || "",
        label: auth.label || "",
        passphrase: auth.passphrase || "",
      };
    }
    if (auth.kind === "keyData") {
      return {
        kind: "keyData",
        label: auth.label || "",
        privateKey: auth.privateKey || auth.private_key || "",
        passphrase: auth.passphrase || "",
      };
    }
    if (auth.kind === "keyFile") {
      return { kind: "keyFile", path: auth.path || "", passphrase: auth.passphrase || "" };
    }
    return auth;
  }
  if (auth.KeyFile) {
    return {
      kind: "keyFile",
      path: auth.KeyFile.path || "",
      passphrase: auth.KeyFile.passphrase || "",
    };
  }
  if (auth.Password) {
    return { kind: "password", password: auth.Password.password || "" };
  }
  return { kind: "password", password: "" };
}

function authForRust(auth) {
  if (!auth) return auth;
  const a = clone(auth);
  if (a.kind === "keyRef") {
    a.key_id = a.keyId;
    delete a.keyId;
  }
  if (a.kind === "keyData") {
    a.private_key = a.privateKey;
    delete a.privateKey;
  }
  return a;
}

function hostForRust(host) {
  const h = clone(host);
  if (h.auth) h.auth = authForRust(h.auth);
  return h;
}

async function call(command, args = {}) {
  if (!invoke) throw new Error("Tauri invoke is unavailable. Please run this inside the Tauri app.");
  const payload = { ...args };
  if (payload.profile) payload.profile = hostForRust(payload.profile);
  if (payload.hosts && command === "save_hosts") payload.hosts = payload.hosts.map(hostForRust);
  if (payload.profiles && command === "save_group_profiles") {
    const newProfiles = {};
    for (const [k, v] of Object.entries(payload.profiles)) newProfiles[k] = hostForRust(v);
    payload.profiles = newProfiles;
  }
  return invoke(command, payload);
}

function init() {
  document.documentElement.lang = currentLocale();
  document.addEventListener("click", handleGlobalClick);
  // No native browser context menu anywhere; custom menus call preventDefault themselves.
  document.addEventListener("contextmenu", (event) => event.preventDefault());
  bindComboEvents();
  bindSftpEvents();
  bindCommandPanelEvents();
  bindPackageFieldEvents();
  bindDragAndDrop();
  bindRipples();
  document.addEventListener("change", (event) => {
    const input = event.target.closest?.('input[data-combo-action="change-net-iface"]');
    if (!input?.value) return;
    state.selectedNetInterface = input.value;
    refreshMonitorPanel();
  });
  state.hosts = [emptyHost()];
  state.selectedHostId = state.hosts[0].id;
  state.status = t("Loading hosts...");
  render();
  loadInitialHosts();
}

async function loadInitialHosts() {
  state.groupProfiles = loadGroupProfiles();
  state.keys = loadKeychain();
  state.identities = loadIdentities();
  state.snippets = loadSnippets();
  state.snippetPackages = loadSnippetPackages();
  migrateSnippetPackages();
  state.cmdOptions = loadCommandEditorOptions();
  state.shellHistory = loadShellHistory();
  state.logs = loadLogs();
  try {
    const [loadedHosts, knownHosts] = await Promise.all([
      call("load_hosts").catch(() => []),
      call("load_known_hosts").catch(() => [])
    ]);
    if (loadedHosts && loadedHosts.length) {
      state.hosts = loadedHosts.map(ensureHost);
    }
    if (knownHosts && knownHosts.length) {
      state.knownHosts = knownHosts;
    }
    state.status = t("Ready");
    if (!state.hosts.length) state.hosts = [emptyHost()];
    state.selectedHostId = state.hosts[0]?.id ?? null;
    state.status = t("Ready");
    pushLog("App", `Loaded ${state.hosts.length} host profile(s).`);
  } catch (error) {
    state.hosts = [emptyHost()];
    state.selectedHostId = state.hosts[0].id;
    pushLog("App", `Load hosts failed: ${error}`);
    state.status = t("Load hosts failed: {0}", error);
  }
  render();
}

function emptyKey() {
  return {
    id: `key-${Date.now()}`,
    label: "",
    privateKey: "",
    publicKey: "",
  };
}

function emptyKeyGenerator() {
  return {
    label: "",
    keyType: "ed25519",
    ecdsaSize: 521,
    rsaSize: 4096,
  };
}

function normalizeKey(key = {}) {
  const normalized = {
    ...emptyKey(),
    ...key,
    id: key.id || `key-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    label: key.label || key.name || "",
    privateKey: key.privateKey || key.private_key || "",
    publicKey: key.publicKey || key.public_key || "",
  };
  delete normalized.name;
  delete normalized.private_key;
  delete normalized.public_key;
  return normalized;
}

function keyIsBlank(key) {
  return !String(key?.label || "").trim() && !String(key?.privateKey || "").trim() && !String(key?.publicKey || "").trim();
}

function loadKeychain() {
  try {
    const raw = window.localStorage?.getItem(KEYCHAIN_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(normalizeKey).filter((key) => !keyIsBlank(key)) : [];
  } catch {
    return [];
  }
}

function persistKeychain() {
  try {
    window.localStorage?.setItem(KEYCHAIN_KEY, JSON.stringify(state.keys));
  } catch (error) {
    pushLog("Keychain", `Save keychain failed: ${error}`);
  }
}

function loadIdentities() {
  try {
    const raw = window.localStorage?.getItem(IDENTITIES_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistIdentities() {
  try {
    window.localStorage?.setItem(IDENTITIES_KEY, JSON.stringify(state.identities));
  } catch (error) {
    pushLog("Keychain", `Save identities failed: ${error}`);
  }
}

function rawValue(id) {
  return document.querySelector(`#${id}`)?.value ?? "";
}

function keyLabel(key) {
  return key?.label?.trim() || t("Add a label...");
}

function identityLabel(ident) {
  return ident?.label?.trim() || t("Add a label...");
}

function keyType(key) {
  const text = `${key?.privateKey || ""}\n${key?.publicKey || ""}`.toLowerCase();
  if (text.includes("ed25519")) return t("Type {0}", "ED25519");
  if (text.includes("rsa")) return t("Type {0}", "RSA");
  if (text.includes("ecdsa")) return t("Type {0}", "ECDSA");
  return t("Type unknown");
}

function privateKeyInvalid(key) {
  const text = (key?.privateKey || "").trim();
  if (!text) return false;
  return !(
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*-----END [A-Z ]*PRIVATE KEY-----/.test(text) ||
    text.startsWith("PuTTY-User-Key-File-")
  );
}

function publicKeyInvalid(key) {
  const text = (key?.publicKey || "").trim();
  if (!text) return false;
  return !/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-[A-Za-z0-9-]+|sk-[A-Za-z0-9-]+)\s+[A-Za-z0-9+/=]+/.test(text);
}

function labelInvalid(key) {
  const text = (key?.label || "").trim();
  return Boolean(text) && !/^[A-Za-z0-9 _.-]+$/.test(text);
}

function isKeyAuth(auth) {
  return ["keyFile", "keyRef", "keyData"].includes(normalizeAuth(auth).kind);
}

function authLabel(auth) {
  return isKeyAuth(auth) ? "key" : "password";
}

function firstKeyRef(passphrase = "") {
  const key = state.keys[0];
  return {
    kind: "keyRef",
    keyId: key?.id || "",
    label: key?.label || "",
    passphrase,
  };
}

function toKeyAuth(auth) {
  const current = normalizeAuth(auth);
  if (current.kind === "keyRef") return current;
  if (current.kind === "keyFile" && current.path) return current;
  if (current.kind === "keyData") return current;
  return firstKeyRef(current.passphrase || "");
}

function selectedKey(keyId) {
  return state.keys.find((key) => key.id === keyId) || null;
}

function resolveAuth(auth) {
  const current = normalizeAuth(auth);
  if (current.kind !== "keyRef") return current;
  const key = selectedKey(current.keyId);
  if (!key) return current;
  return {
    kind: "keyData",
    label: key.label || "Keychain key",
    privateKey: key.privateKey || "",
    passphrase: current.passphrase || "",
  };
}

function profileForConnection(host) {
  const profile = ensureHost(clone(host));
  if (profile.identityId) {
    const ident = state.identities.find((i) => i.id === profile.identityId);
    if (ident) {
      profile.username = ident.username || "root";
      profile.auth = resolveAuth(ident.auth);
      return profile;
    }
  }
  profile.auth = resolveAuth(profile.auth);
  return profile;
}

function renderKeySelect(id, auth, attrs = "") {
  const current = normalizeAuth(auth);
  const selectedId = current.kind === "keyRef" ? current.keyId : "";
  const selected = selectedId || state.keys[0]?.id || "";
  const options = state.keys.map((key) => ({ value: key.id, label: keyLabel(key) }));
  return `
    <div class="detail-field">
      <label>${t("Key")}</label>
      ${renderMdSelect(id, options, selected, {
        disabled: /\bdisabled\b/.test(attrs),
        placeholder: t("No keys saved"),
        icon: keySmallIcon(),
      })}
    </div>
  `;
}

/* --------------------------------------------------------------------------
   MD3 menus replacing native <select> / <datalist>.
   The popup lives on <body> (position: fixed) so scroll containers never clip
   it, and it re-anchors by id after each render().
   -------------------------------------------------------------------------- */
// Read-only dropdown: a hidden input holds the value, a button shows the label.
function renderMdSelect(id, options, selected, { disabled = false, placeholder = "", icon = "", compact = false, action = "" } = {}) {
  const current = options.find((option) => option.value === selected) || null;
  const isDisabled = disabled || !options.length;
  return `
    <div class="md-combo md-select ${compact ? "compact" : ""} ${isDisabled ? "disabled" : ""}" data-combo-for="${escapeAttr(id)}" data-combo-mode="select" data-options="${escapeAttr(JSON.stringify(options))}">
      <input type="hidden" id="${escapeAttr(id)}" value="${escapeAttr(current ? current.value : "")}" ${action ? `data-combo-action="${escapeAttr(action)}"` : ""} />
      <button type="button" class="md-combo-trigger" id="${escapeAttr(id)}__trigger" ${isDisabled ? "disabled" : ""}>
        ${icon ? `<span class="md-combo-lead">${icon}</span>` : ""}
        <span class="md-combo-label truncate-text ${current ? "" : "placeholder"}">${escapeHtml(current ? current.label : placeholder)}</span>
        <span class="md-combo-chevron">${chevronDownIcon()}</span>
      </button>
    </div>
  `;
}

// Editable combobox with filtered suggestions (Termius-style group picker).
function renderMdCombo(id, options, currentValue, { placeholder = "", icon = "", clearable = true } = {}) {
  return `
    <div class="md-combo md-combobox ${currentValue ? "has-value" : ""} ${clearable ? "" : "no-clear"}" data-combo-for="${escapeAttr(id)}" data-combo-mode="combo" data-options="${escapeAttr(JSON.stringify(options))}">
      ${icon ? `<span class="md-combo-lead">${icon}</span>` : ""}
      <input id="${escapeAttr(id)}" class="md-combo-input" value="${escapeAttr(currentValue || "")}" placeholder="${escapeAttr(placeholder)}" autocomplete="off" spellcheck="false" />
      <button type="button" class="md-combo-clear" tabindex="-1" title="${t("Clear")}">${closeIcon()}</button>
      <span class="md-combo-chevron">${chevronDownIcon()}</span>
    </div>
  `;
}

let activeCombo = null; // { id, highlight }
let comboMenuEl = null;

function comboRoot(id) {
  return document.querySelector(`.md-combo[data-combo-for="${CSS.escape(id)}"]`);
}

function comboFilteredOptions(root) {
  let options = [];
  try {
    options = JSON.parse(root.dataset.options || "[]");
  } catch {
    options = [];
  }
  if (root.dataset.comboMode !== "combo") return options;
  const query = (root.querySelector("input")?.value || "").trim().toLowerCase();
  if (!query || !root.classList.contains("filtering")) return options;
  return options.filter((option) => option.label.toLowerCase().includes(query));
}

function openCombo(id, highlight) {
  const root = comboRoot(id);
  if (!root || root.classList.contains("disabled")) return;
  const input = root.querySelector("input");
  if (highlight === undefined) {
    highlight = Math.max(0, comboFilteredOptions(root).findIndex((option) => option.value === input.value));
  }
  if (activeCombo && activeCombo.id !== id) closeCombo();
  activeCombo = { id, highlight };
  drawComboMenu();
}

function closeCombo() {
  if (activeCombo) comboRoot(activeCombo.id)?.classList.remove("open", "filtering");
  activeCombo = null;
  comboMenuEl?.remove();
  comboMenuEl = null;
}

function ensureComboMenuEl() {
  if (comboMenuEl) return comboMenuEl;
  comboMenuEl = document.createElement("div");
  comboMenuEl.className = "md-combo-menu";
  comboMenuEl.setAttribute("role", "listbox");
  // mousedown keeps focus in the field so blur does not close the menu first.
  comboMenuEl.addEventListener("mousedown", (event) => event.preventDefault());
  comboMenuEl.addEventListener("click", (event) => {
    event.stopPropagation();
    const item = event.target.closest("[data-combo-index]");
    if (item && activeCombo) pickComboOption(activeCombo.id, Number(item.dataset.comboIndex));
  });
  comboMenuEl.addEventListener("mousemove", (event) => {
    const item = event.target.closest("[data-combo-index]");
    if (!item || !activeCombo) return;
    const index = Number(item.dataset.comboIndex);
    if (index === activeCombo.highlight) return;
    activeCombo.highlight = index;
    comboMenuEl.querySelectorAll("[data-combo-index]").forEach((el) => {
      el.classList.toggle("active", Number(el.dataset.comboIndex) === index);
    });
  });
  document.body.appendChild(comboMenuEl);
  return comboMenuEl;
}

function drawComboMenu() {
  if (!activeCombo) return;
  const root = comboRoot(activeCombo.id);
  if (!root) return closeCombo();
  const options = comboFilteredOptions(root);
  if (!options.length) {
    root.classList.remove("open");
    comboMenuEl?.remove();
    comboMenuEl = null;
    return;
  }
  activeCombo.highlight = Math.min(Math.max(activeCombo.highlight, 0), options.length - 1);
  const currentValue = root.querySelector("input").value;
  const menu = ensureComboMenuEl();
  menu.innerHTML = options
    .map(
      (option, index) => `
        <div class="md-combo-option ${index === activeCombo.highlight ? "active" : ""} ${option.value === currentValue ? "selected" : ""}" role="option" data-combo-index="${index}">
          <span class="truncate-text">${escapeHtml(option.label)}</span>
          ${option.value === currentValue ? `<span class="md-combo-check">${checkIcon()}</span>` : ""}
        </div>
      `,
    )
    .join("");
  root.classList.add("open");
  positionComboMenu();
  menu.querySelector(".md-combo-option.active")?.scrollIntoView({ block: "nearest" });
}

function positionComboMenu() {
  if (!activeCombo || !comboMenuEl) return;
  const root = comboRoot(activeCombo.id);
  if (!root) return closeCombo();
  const rect = root.getBoundingClientRect();
  const gap = 4;
  const margin = 8;
  const below = window.innerHeight - rect.bottom - gap - margin;
  const above = rect.top - gap - margin;
  comboMenuEl.style.maxHeight = "280px";
  const natural = Math.min(comboMenuEl.scrollHeight, 280);
  const openUp = below < natural && above > below;
  const maxHeight = Math.max(80, Math.min(280, openUp ? above : below));
  const width = Math.max(rect.width, 140);
  comboMenuEl.style.width = `${width}px`;
  comboMenuEl.style.left = `${Math.min(rect.left, window.innerWidth - width - margin)}px`;
  comboMenuEl.style.maxHeight = `${maxHeight}px`;
  comboMenuEl.style.top = openUp ? "auto" : `${rect.bottom + gap}px`;
  comboMenuEl.style.bottom = openUp ? `${window.innerHeight - rect.top + gap}px` : "auto";
  comboMenuEl.classList.toggle("up", openUp);
}

function pickComboOption(id, index) {
  const root = comboRoot(id);
  if (!root) return closeCombo();
  const option = comboFilteredOptions(root)[index];
  if (!option) return;
  const input = root.querySelector("input");
  input.value = option.value;
  if (root.dataset.comboMode === "select") {
    const label = root.querySelector(".md-combo-label");
    label.textContent = option.label;
    label.classList.remove("placeholder");
  } else {
    root.classList.toggle("has-value", Boolean(input.value));
  }
  closeCombo();
  if (root.dataset.comboMode === "select") root.querySelector(".md-combo-trigger")?.focus();
  else input.focus();
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

// Called at the end of render(): keep an open menu attached to the new DOM.
function syncComboAfterRender() {
  if (!activeCombo) return;
  if (!comboRoot(activeCombo.id)) return closeCombo();
  drawComboMenu();
}

function bindComboEvents() {
  document.addEventListener(
    "click",
    (event) => {
      if (event.target.closest(".md-combo-menu")) return;
      const root = event.target.closest(".md-combo");
      if (!root) {
        if (activeCombo) closeCombo();
        return;
      }
      // Keep the app's global click handlers (menu closing, card deselect) out of it.
      event.stopPropagation();
      const id = root.dataset.comboFor;
      if (root.classList.contains("disabled")) return;
      if (event.target.closest(".md-combo-clear")) {
        const input = root.querySelector("input");
        input.value = "";
        root.classList.remove("has-value", "filtering");
        input.focus();
        openCombo(id, 0);
        return;
      }
      if (root.dataset.comboMode === "select") {
        if (activeCombo?.id === id) closeCombo();
        else openCombo(id);
        return;
      }
      const input = root.querySelector("input");
      if (document.activeElement !== input) input.focus();
      if (activeCombo?.id === id && event.target.closest(".md-combo-chevron")) closeCombo();
      else if (activeCombo?.id !== id) openCombo(id);
    },
    true,
  );

  document.addEventListener("focusin", (event) => {
    const input = event.target.closest?.(".md-combo-input");
    if (input && activeCombo?.id !== input.id) openCombo(input.id);
  });

  document.addEventListener("focusout", (event) => {
    const root = event.target.closest?.(".md-combo");
    if (!root) return;
    const id = root.dataset.comboFor;
    setTimeout(() => {
      if (activeCombo?.id !== id) return;
      const current = comboRoot(id);
      // A render() may have swapped the DOM; only close if focus really left.
      if (!current || !current.contains(document.activeElement)) closeCombo();
    }, 0);
  });

  document.addEventListener("input", (event) => {
    const input = event.target.closest?.(".md-combo-input");
    if (!input) return;
    const root = input.closest(".md-combo");
    root.classList.toggle("has-value", Boolean(input.value));
    root.classList.add("filtering");
    openCombo(input.id, 0);
  });

  document.addEventListener(
    "keydown",
    (event) => {
      const root = event.target.closest?.(".md-combo");
      if (!root) return;
      const id = root.dataset.comboFor;
      const isOpen = activeCombo?.id === id && comboMenuEl;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (!isOpen) return openCombo(id);
        const count = comboFilteredOptions(root).length;
        activeCombo.highlight = (activeCombo.highlight + (event.key === "ArrowDown" ? 1 : -1) + count) % count;
        drawComboMenu();
      } else if (event.key === "Enter" && isOpen) {
        event.preventDefault();
        event.stopPropagation();
        pickComboOption(id, activeCombo.highlight);
      } else if (event.key === "Escape" && isOpen) {
        event.preventDefault();
        event.stopPropagation();
        closeCombo();
      } else if (event.key === "Tab" && isOpen) {
        closeCombo();
      }
    },
    true,
  );

  window.addEventListener("resize", positionComboMenu);
  document.addEventListener(
    "scroll",
    (event) => {
      if (comboMenuEl && !comboMenuEl.contains(event.target)) positionComboMenu();
    },
    true,
  );
}

function loadGroupProfiles() {
  try {
    const raw = window.localStorage?.getItem(GROUP_PROFILES_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return Object.fromEntries(
      Object.entries(parsed || {})
        .map(([name, profile]) => {
          const normalized = normalizeGroupProfile(name, profile);
          return normalized.name ? [normalized.name, normalized] : null;
        })
        .filter(Boolean),
    );
  } catch {
    return {};
  }
}

function persistGroupProfiles() {
  try {
    window.localStorage?.setItem(GROUP_PROFILES_KEY, JSON.stringify(state.groupProfiles));
  } catch (error) {
    pushLog("App", `Save group profiles failed: ${error}`);
  }
}

function loadLogs() {
  try {
    const raw = window.localStorage?.getItem(LOGS_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function persistLogs() {
  try {
    window.localStorage?.setItem(LOGS_KEY, JSON.stringify(state.logs));
  } catch (error) {
    // 忽略存储日志时的报错，防止程序崩溃
  }
}

function setStatus(message, options = {}) {
  state.status = String(message || "Ready");
  render(options);
}

function pushLog(kind, message, host = null) {
  if (kind !== "SSH" && kind !== "Terminal") return;
  
  const isStart = String(message).startsWith("Connected to") || message === "Opened local PowerShell.";
  const isEnd = message === t("Disconnected") + "." || message === "Closed local terminal.";
  if (!isStart && !isEnd) return;

  const targetHostObj = host || state.activeHost || null;
  const targetHost = targetHostObj?.name || "";
  const targetHostId = targetHostObj?.id || "";
  const targetHostOs = targetHostObj?.os || "";
  const now = Date.now();

  if (isEnd) {
    const lastLog = state.logs.find(l => l.kind === kind && (l.hostId ? l.hostId === targetHostId : l.host === targetHost));
    if (lastLog) {
      lastLog.endTimestamp = now;
      persistLogs();
    }
    return;
  }

  const newLog = {
    time: new Date().toLocaleString(),
    timestamp: now,
    endTimestamp: now,
    kind,
    message: String(message || ""),
    host: targetHost,
    hostId: targetHostId,
    os: targetHostOs,
    user: host?.username || state.activeHost?.username || "",
  };

  if (state.logs.length > 0) {
    const lastLog = state.logs[0];
    if (lastLog.host === newLog.host && (now - (lastLog.timestamp || 0)) < 60000) {
      return;
    }
  }

  state.logs.unshift(newLog);
  state.logs = state.logs.slice(0, 300);
  persistLogs();
}

function closeMenus() {
  state.hostMenuOpen = false;
  state.keyMenuOpen = false;
  state.languageMenuOpen = false;
  state.snippetMenuOpen = false;
  state.hostIdentityMenuOpen = false;
  state.sortMenuOpen = false;
  state.contextMenu = null;
}

function groups() {
  return allGroupPaths().map((path) => [path, hostsInGroup(path).length]);
}

function normalizeGroupPath(value) {
  const parts = String(value || "")
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.join("/");
}

function groupLabel(path) {
  return normalizeGroupPath(path).split("/").pop() || "Ungrouped";
}

function parentGroupPath(path) {
  const parts = normalizeGroupPath(path).split("/");
  parts.pop();
  return parts.join("/");
}

function joinGroupPath(parent, name) {
  const label = String(name || "").trim();
  if (!label) return normalizeGroupPath(parent || "Default");
  return parent ? normalizeGroupPath(`${parent}/${label}`) : normalizeGroupPath(label);
}

function groupPathWithin(path, parent) {
  const normalizedPath = normalizeGroupPath(path);
  const normalizedParent = normalizeGroupPath(parent);
  if (!normalizedParent) return true; // 如果父路径为空，说明在根目录，直接返回true
  if (!normalizedPath) return false;
  return normalizedPath === normalizedParent || normalizedPath.startsWith(`${normalizedParent}/`);
}

function allGroupPaths() {
  const paths = new Set();
  for (const name of Object.keys(state.groupProfiles || {})) {
    const path = normalizeGroupPath(name);
    if (!path) continue;
    const parts = path.split("/");
    for (let index = 1; index <= parts.length; index += 1) {
      paths.add(parts.slice(0, index).join("/"));
    }
  }
  for (const host of state.hosts) {
    const path = normalizeGroupPath(host.group || "");
    if (!path) continue;
    const parts = path.split("/");
    for (let index = 1; index <= parts.length; index += 1) {
      paths.add(parts.slice(0, index).join("/"));
    }
  }
  return [...paths].sort((a, b) => a.localeCompare(b));
}

function groupParentOptions(currentName = "") {
  const current = normalizeGroupPath(currentName);
  return allGroupPaths()
    .filter((path) => path !== current && !groupPathWithin(path, current))
    .map((path) => ({ value: path, label: path }));
}

function groupChildren(parent = state.openedGroup) {
  const normalizedParent = parent ? normalizeGroupPath(parent) : null;
  const children = allGroupPaths()
    .filter((path) => parentGroupPath(path) === normalizedParent)
    .map((path) => [path, hostsInGroup(path).length]);
  return children.sort((a, b) => groupLabel(a[0]).localeCompare(groupLabel(b[0])));
}

function emptyGroupProfile(name = "New Group") {
  return {
    name,
    originalName: name,
    port: 22,
    username: "root",
    useCredentials: false,
    auth: { kind: "password", password: "" },
  };
}

function normalizeGroupProfile(name, profile = {}) {
  return {
    ...emptyGroupProfile(name),
    ...profile,
    name: normalizeGroupPath(profile.name || name || "Default"),
    originalName: profile.originalName || name || profile.name || "Default",
    port: Number(profile.port || 22),
    username: profile.username || "root",
    useCredentials: Boolean(profile.useCredentials),
    auth: normalizeAuth(profile.auth),
  };
}

function nextGroupName() {
  const existing = new Set(allGroupPaths());
  const parent = state.openedGroup ? normalizeGroupPath(state.openedGroup) : null;
  let name = joinGroupPath(parent, "New Group");
  let index = 2;
  while (existing.has(name)) {
    name = joinGroupPath(parent, `New Group ${index}`);
    index += 1;
  }
  return name;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function selectedHost() {
  return state.hosts.find((host) => host.id === state.selectedHostId) || state.hosts[0] || null;
}

function applySort(list, getName, getDate) {
  let sorted = [...list];
  if (state.sortMode === "a-z" || state.sortMode === "z-a") {
    sorted.sort((a, b) => {
      const nameA = String(getName(a) || "").toLowerCase();
      const nameB = String(getName(b) || "").toLowerCase();
      return state.sortMode === "a-z" ? nameA.localeCompare(nameB) : nameB.localeCompare(nameA);
    });
  } else if (getDate) {
    sorted.sort((a, b) => {
      return state.sortMode === "oldest" ? getDate(a) - getDate(b) : getDate(b) - getDate(a);
    });
  } else if (state.sortMode === "oldest") {
    sorted = sorted.reverse();
  }
  return sorted;
}

function filteredHosts() {
  const q = state.search.trim().toLowerCase();
  const results = state.hosts.filter((host) => {
    const hostGroup = host.group || "";
    let groupOk;
    if (q) {
      groupOk = true;
    } else if (state.openedGroup) {
      groupOk = groupPathWithin(hostGroup, state.openedGroup);
    } else {
      groupOk = true;
    }
    const searchOk =
      !q ||
      host.name.toLowerCase().includes(q) ||
      host.host.toLowerCase().includes(q) ||
      host.username.toLowerCase().includes(q);
    return groupOk && searchOk;
  });
  
  return applySort(results, (h) => h.name || h.host, (h) => {
    let last = 0;
    const logs = state.logs || [];
    for (let i = 0; i < logs.length; i++) {
      if (logs[i].host === h.name) {
        const t = logs[i].timestamp || 0;
        if (t > last) last = t;
      }
    }
    return last || (1000 + state.hosts.indexOf(h));
  });
}

async function saveHosts() {
  await call("save_hosts", { hosts: state.hosts });
}

function openEditor(host = null) {
  syncFormsToState();
  const source = host || emptyHost();
  const targetGroup = state.selectedGroup || state.openedGroup;
  if (!host && targetGroup) {
    source.group = targetGroup;
    const profile = state.groupProfiles[source.group];
    if (profile?.useCredentials) {
      source.port = profile.port;
      source.username = profile.username;
      source.auth = clone(profile.auth);
    }
  }
  state.editingIndex = host ? state.hosts.findIndex((item) => item.id === host.id) : -1;
  state.editingHost = clone(source);
  state.detailKind = "host";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingGroup = null;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function openGroupDetails(group = nextGroupName()) {
  syncFormsToState();
  const profile = state.groupProfiles[group] || emptyGroupProfile(group);
  state.editingGroup = normalizeGroupProfile(group, profile);
  state.editingGroup.originalName = group;
  state.detailKind = "group";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingHost = null;
  state.editingIndex = -1;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function openIdentityDetails(ident = null) {
  syncFormsToState();
  state.section = "keychain";
  const index = ident ? state.identities.findIndex((item) => item.id === ident.id) : -1;
  state.editingIdentityIndex = index;
  state.editingIdentity = index >= 0 ? clone(state.identities[index]) : emptyIdentity();
  state.selectedIdentityId = index >= 0 ? state.identities[index].id : null;
  state.detailKind = "identity";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingHost = null;
  state.editingGroup = null;
  state.editingKey = null;
  state.editingIndex = -1;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function openKeyDetails(key = null) {
  syncFormsToState();
  state.section = "keychain";
  const index = key ? state.keys.findIndex((item) => item.id === key.id) : -1;
  state.editingKeyIndex = index;
  state.editingKey = index >= 0 ? clone(state.keys[index]) : emptyKey();
  state.selectedKeyId = index >= 0 ? state.keys[index].id : null;
  state.detailKind = "key";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingHost = null;
  state.editingGroup = null;
  state.editingIndex = -1;
  state.keyGenerator = null;
  state.keyGenerating = false;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function openGenerateKeyDetails() {
  syncFormsToState();
  state.section = "keychain";
  state.keyGenerator = emptyKeyGenerator();
  state.keyGenerating = false;
  state.detailKind = "generateKey";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingHost = null;
  state.editingGroup = null;
  state.editingKey = null;
  state.editingIndex = -1;
  state.editingKeyIndex = -1;
  state.selectedKeyId = null;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function closeEditor() {
  state.editorOpen = false;
  state.detailOpen = false;
  state.detailKind = null;
  state.editingHost = null;
  state.editingGroup = null;
  state.editingKey = null;
  state.editingSnippet = null;
  state.editingPackage = null;
  state.editingIndex = -1;
  state.editingKeyIndex = -1;
  state.editingSnippetIndex = -1;
  state.keyGenerator = null;
  state.keyGenerating = false;
  render();
}

async function saveEditor(options = {}) {
  const host = ensureHost(state.editingHost);
  if (!host.name.trim()) return setStatus(t("Name is required"));
  if (!host.group.trim()) return setStatus(t("Group is required"));
  if (!host.host.trim()) return setStatus(t("Host is required"));
  if (!String(host.port).trim()) return setStatus(t("Port is required"));
  if (!host.identityId) {
    if (!host.username.trim()) return setStatus(t("Username is required"));
    if (host.auth.kind === "keyFile" && !host.auth.path.trim()) return setStatus(t("Private key path is required"));
    if (host.auth.kind === "keyRef" && !host.auth.keyId) return setStatus(t("Choose a key from Keychain first"));
    if (host.auth.kind === "password" && !host.auth.password) return setStatus(t("Password is required"));
  }

  if (state.editingIndex >= 0) {
    state.hosts[state.editingIndex] = host;
  } else {
    state.hosts.push(host);
  }
  state.selectedHostId = host.id;
  await saveHosts();
  if (!options.keepOpen) closeEditor();
  pushLog("Host", `Saved ${host.name}.`, host);
  setStatus(t("Host saved"));
  return host;
}

function requestDeleteConfirmation(dialog) {
  if (deleteDialogResolver) {
    const previousResolver = deleteDialogResolver;
    deleteDialogResolver = null;
    previousResolver(false);
  }
  return new Promise((resolve) => {
    deleteDialogResolver = resolve;
    state.deleteDialog = dialog;
    state.contextMenu = null;
    render();
  });
}

function resolveDeleteConfirmation(confirmed) {
  const resolve = deleteDialogResolver;
  deleteDialogResolver = null;
  state.deleteDialog = null;
  render();
  if (resolve) resolve(Boolean(confirmed));
}

async function deleteHost(hostId) {
  const index = state.hosts.findIndex((host) => host.id === hostId);
  if (index < 0) return;
  const host = state.hosts[index];
  const confirmed = await requestDeleteConfirmation({
    title: t("Remove a host"),
    message: t("You are going to remove this host:"),
    item: {
      type: "host",
      title: host.name || host.host || t("Unnamed host"),
      subtitle: `ssh, ${host.username || "user"}`,
      os: host.os,
    },
  });
  if (!confirmed) return;
  if (state.editingHost?.id === hostId) closeEditor();
  state.hosts.splice(index, 1);
  if (!state.hosts.length) state.hosts.push(emptyHost());
  state.selectedHostId = state.hosts[Math.min(index, state.hosts.length - 1)].id;
  await saveHosts();
  pushLog("Host", `Deleted ${host.name}.`, host);
  setStatus(t("Host deleted"));
  render();
}

async function duplicateHost(hostId) {
  const host = state.hosts.find((item) => item.id === hostId);
  if (!host) return;
  const copy = ensureHost({
    ...clone(host),
    id: `host-${Date.now()}`,
    name: `${host.name} Copy`,
  });
  state.hosts.push(copy);
  state.selectedHostId = copy.id;
  state.selectedGroup = null;
  await saveHosts();
  pushLog("Host", `Duplicated ${host.name}.`, copy);
  setStatus(t("Host duplicated"));
}

function hostsInGroup(group) {
  return state.hosts.filter((host) => groupPathWithin(host.group || "Default", group));
}

function openGroup(group) {
  state.selectedGroup = group;
  state.openedGroup = group;
  state.selectedHostId = null;
  closeEditor();
  setStatus(t("Opened group {0}", group));
}

function showAllHosts() {
  state.openedGroup = null;
  state.selectedGroup = null;
  render();
}

function connectGroup(group) {
  const hosts = hostsInGroup(group);
  if (!hosts.length) return setStatus(t("Group {0} has no hosts", group));
  state.selectedGroup = group;
  state.openedGroup = group;
  if (hosts.length > 1) pushLog("Group", `Connecting first host in ${group}; multi-tab group sessions are not enabled yet.`);
  connectHost(hosts[0]);
}

async function removeGroup(group) {
  const affectedHosts = hostsInGroup(group);
  const groupName = normalizeGroupPath(group).split("/").filter(Boolean).slice(-1)[0] || group;
  const confirmed = await requestDeleteConfirmation({
    title: affectedHosts.length ? t("Remove a group and hosts") : t("Remove a group"),
    message: t("You are going to remove this group:"),
    item: {
      type: "group",
      title: groupName,
      subtitle: hostCountLabel(affectedHosts.length),
    },
    affectedLabel: t("And these hosts:"),
    affected: affectedHosts.map((host) => ({
      type: "host",
      title: host.name || host.host || t("Unnamed host"),
      subtitle: `ssh, ${host.username || "user"}`,
      os: host.os,
    })),
  });
  if (!confirmed) return;
  if (
    state.editingGroup &&
    normalizeGroupPath(state.editingGroup.originalName || state.editingGroup.name) === normalizeGroupPath(group)
  ) {
    closeEditor();
  }
  state.hosts = state.hosts.filter((host) => !groupPathWithin(host.group || "Default", group));
  for (const path of Object.keys(state.groupProfiles || {})) {
    if (groupPathWithin(path, group)) delete state.groupProfiles[path];
  }
  persistGroupProfiles();
  if (!state.hosts.length) state.hosts.push(emptyHost());
  state.selectedGroup = null;
  state.openedGroup = null;
  state.selectedHostId = state.hosts[0]?.id ?? null;
  await saveHosts();
  pushLog("Group", `Removed ${group}.`);
  setStatus(t("Group removed"));
  render();
}

async function createGroupFromMenu() {
  openGroupDetails(nextGroupName());
}

async function saveGroupDetails() {
  if (!state.editingGroup) return;
  readGroupDetails();
  const profile = normalizeGroupProfile(state.editingGroup.originalName, state.editingGroup);
  if (!profile.name.trim()) return setStatus(t("Group name is required"));
  if (profile.useCredentials) {
    if (!profile.username.trim()) return setStatus(t("Group username is required"));
    if (profile.auth.kind === "password" && !profile.auth.password) return setStatus(t("Group password is required"));
    if (profile.auth.kind === "keyFile" && !profile.auth.path.trim()) return setStatus(t("Group key path is required"));
    if (profile.auth.kind === "keyRef" && !profile.auth.keyId) return setStatus(t("Choose a group key from Keychain first"));
  }

  const oldName = profile.originalName || profile.name;
  if (oldName !== profile.name) {
    for (const host of state.hosts) {
      if (groupPathWithin(host.group || "Default", oldName)) {
        host.group = profile.name + normalizeGroupPath(host.group).slice(normalizeGroupPath(oldName).length);
      }
    }

    const updatedProfiles = {};
    for (const [path, item] of Object.entries(state.groupProfiles || {})) {
      if (groupPathWithin(path, oldName)) {
        const nextPath = profile.name + normalizeGroupPath(path).slice(normalizeGroupPath(oldName).length);
        updatedProfiles[nextPath] = { ...item, name: nextPath };
      } else {
        updatedProfiles[path] = item;
      }
    }
    state.groupProfiles = updatedProfiles;
    if (state.openedGroup && groupPathWithin(state.openedGroup, oldName)) {
      state.openedGroup = profile.name + normalizeGroupPath(state.openedGroup).slice(normalizeGroupPath(oldName).length);
    }
    if (state.selectedGroup && groupPathWithin(state.selectedGroup, oldName)) {
      state.selectedGroup = profile.name + normalizeGroupPath(state.selectedGroup).slice(normalizeGroupPath(oldName).length);
    }
  }

  if (profile.useCredentials) {
    for (const host of state.hosts) {
      if (groupPathWithin(host.group || "Default", profile.name)) {
        host.port = profile.port;
        host.username = profile.username;
        host.auth = clone(profile.auth);
      }
    }
  }

  state.groupProfiles[profile.name] = {
    name: profile.name,
    port: profile.port,
    username: profile.username,
    useCredentials: profile.useCredentials,
    auth: clone(profile.auth),
  };
  state.selectedGroup = profile.name;
  persistGroupProfiles();
  await saveHosts();
  closeEditor();
  pushLog("Group", `Saved ${profile.name}.`);
  setStatus(t("Group saved"));
}

function saveKeyDetails(options = {}) {
  if (!state.editingKey) return;
  if (options.readForm !== false) readKeyDetails();
  const key = normalizeKey(state.editingKey);
  if (state.editingKeyIndex < 0 && keyIsBlank(key)) {
    state.selectedKeyId = null;
    closeEditor();
    setStatus(t("Blank key discarded"));
    return;
  }

  const existingIndex = state.keys.findIndex((item) => item.id === key.id);
  if (existingIndex >= 0) {
    state.keys[existingIndex] = clone(key);
    state.editingKeyIndex = existingIndex;
  } else {
    state.keys.unshift(clone(key));
    state.editingKeyIndex = 0;
  }
  state.selectedKeyId = key.id;
  state.editingKey = clone(key);
  persistKeychain();
  setStatus(t("Key saved"));
}

function readKeyGenerator() {
  if (!state.keyGenerator) state.keyGenerator = emptyKeyGenerator();
  state.keyGenerator.label = rawValue("generateKeyLabel");
}

async function generateAndSaveKey() {
  if (!state.keyGenerator) state.keyGenerator = emptyKeyGenerator();
  readKeyGenerator();
  const generator = { ...emptyKeyGenerator(), ...state.keyGenerator };
  const keyTypeName = generator.keyType || "ed25519";
  const label = generator.label.trim() || keyTypeName;

  state.keyGenerating = true;
  render();

  try {
    const generated = await call("generate_ssh_key", {
      keyType: keyTypeName,
      ecdsaSize: Number(generator.ecdsaSize || 521),
      rsaSize: Number(generator.rsaSize || 4096),
    });
    const key = normalizeKey({
      id: `key-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      label,
      privateKey: generated.privateKey || generated.private_key || "",
      publicKey: generated.publicKey || generated.public_key || "",
    });
    state.keys.unshift(clone(key));
    state.selectedKeyId = key.id;
    state.editingKeyIndex = 0;
    state.editingKey = clone(key);
    state.detailKind = "key";
    state.detailOpen = true;
    state.keyGenerator = null;
    state.keyGenerating = false;
    persistKeychain();
    pushLog("Keychain", `Generated ${keyLabel(key)}.`);
    setStatus(t("Generated {0}", keyLabel(key)));
    render();
  } catch (error) {
    state.keyGenerating = false;
    setStatus(t("Generate key failed: {0}", error));
    render();
  }
}

async function removeKey(keyId) {
  const index = state.keys.findIndex((key) => key.id === keyId);
  if (index < 0) return;
  const key = state.keys[index];
  const confirmed = await requestDeleteConfirmation({
    title: t("Remove key"),
    message: t("Are you sure you want to remove this key?"),
    item: {
      type: "key",
      title: keyLabel(key) || t("Unnamed key"),
      subtitle: keyType(key),
    },
  });
  if (!confirmed) return;
  state.keys.splice(index, 1);
  if (state.selectedKeyId === keyId) {
    state.selectedKeyId = state.keys[Math.min(index, state.keys.length - 1)]?.id || null;
  }
  if (state.editingKey?.id === keyId) closeEditor();
  persistKeychain();
  pushLog("Keychain", `Removed ${keyLabel(key)}.`);
  setStatus(t("Key removed"));
  render();
}

function emptySnippet() {
  return {
    id: `snippet-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    name: "",
    script: "",
    packageId: "",
  };
}

function normalizeSnippet(snippet = {}) {
  return {
    ...emptySnippet(),
    ...snippet,
    id: snippet.id || `snippet-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    name: snippet.name || "",
    script: snippet.script || snippet.command || "",
    packageId: snippet.packageId || "",
  };
}

function snippetIsBlank(snippet) {
  return !String(snippet?.name || "").trim() && !String(snippet?.script || "").trim();
}

function loadSnippets() {
  try {
    const raw = window.localStorage?.getItem(SNIPPETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(normalizeSnippet).filter((s) => !snippetIsBlank(s)) : [];
  } catch {
    return [];
  }
}

function persistSnippets() {
  try {
    window.localStorage?.setItem(SNIPPETS_KEY, JSON.stringify(state.snippets));
  } catch (error) {
    pushLog("Snippets", `Save snippets failed: ${error}`);
  }
}

function snippetLabel(snippet) {
  return snippet?.name?.trim() || "";
}

function openSnippetDetails(snippet = null) {
  syncFormsToState();
  state.section = "snippets";
  const index = snippet ? state.snippets.findIndex((item) => item.id === snippet.id) : -1;
  state.editingSnippetIndex = index;
  state.editingSnippet = index >= 0 ? clone(state.snippets[index]) : emptySnippet();
  if (index < 0 && packageById(state.openedPackageId)) state.editingSnippet.packageId = state.openedPackageId;
  state.editingSnippet.packageName = packageById(state.editingSnippet.packageId)?.name || "";
  state.editingPackage = null;
  state.selectedSnippetId = index >= 0 ? state.snippets[index].id : null;
  state.detailKind = "snippet";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingHost = null;
  state.editingGroup = null;
  state.editingKey = null;
  state.editingIndex = -1;
  state.editingKeyIndex = -1;
  state.keyGenerator = null;
  state.keyGenerating = false;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function saveSnippetDetails() {
  if (!state.editingSnippet) return;
  readSnippetDetails();
  const snippet = normalizeSnippet(state.editingSnippet);
  // Typing a new name in the picker creates that package; clearing it moves
  // the snippet back to Default.
  if ("packageName" in snippet) {
    snippet.packageId = snippetIsBlank(snippet) ? snippet.packageId : ensurePackageNamed(snippet.packageName);
    delete snippet.packageName;
  }
  if (snippetIsBlank(snippet)) {
    state.selectedSnippetId = null;
    closeEditor();
    setStatus(t("Blank snippet discarded"));
    return;
  }

  const existingIndex = state.snippets.findIndex((item) => item.id === snippet.id);
  if (existingIndex >= 0) {
    state.snippets[existingIndex] = clone(snippet);
    state.editingSnippetIndex = existingIndex;
  } else {
    state.snippets.unshift(clone(snippet));
    state.editingSnippetIndex = 0;
  }
  state.selectedSnippetId = snippet.id;
  state.editingSnippet = clone(snippet);
  persistSnippets();
  setStatus(t("Snippet saved"));
}

async function removeSnippet(snippetId) {
  const index = state.snippets.findIndex((s) => s.id === snippetId);
  if (index < 0) return;
  const snippet = state.snippets[index];
  const confirmed = await requestDeleteConfirmation({
    title: t("Remove snippet"),
    message: t("Are you sure you want to remove this snippet?"),
    item: {
      type: "snippet",
      title: snippetLabel(snippet) || t("Unnamed snippet"),
      subtitle: snippet.script || "",
    },
  });
  if (!confirmed) return;
  state.snippets.splice(index, 1);
  if (state.selectedSnippetId === snippetId) {
    state.selectedSnippetId = state.snippets[Math.min(index, state.snippets.length - 1)]?.id || null;
  }
  if (state.editingSnippet?.id === snippetId) closeEditor();
  persistSnippets();
  pushLog("Snippets", `Removed ${snippetLabel(snippet)}.`);
  setStatus(t("Snippet removed"));
  render();
}

function readSnippetDetails() {
  if (!state.editingSnippet || !document.getElementById("snippetName")) return;
  state.editingSnippet.name = rawValue("snippetName");
  state.editingSnippet.script = rawValue("snippetScript");
  state.editingSnippet.packageName = rawValue("snippetPackage");
}

async function createSnippet() {
  openSnippetDetails();
}

function loadShellHistory() {
  try {
    const raw = window.localStorage?.getItem(SHELL_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistShellHistory() {
  try {
    window.localStorage?.setItem(SHELL_HISTORY_KEY, JSON.stringify(state.shellHistory));
  } catch (error) {
    pushLog("Shell History", `Save shell history failed: ${error}`);
  }
}

function recordShellHistory(command) {
  if (!command || !command.trim()) return;
  const entry = {
    command: command.trim(),
    time: Date.now(),
  };
  state.shellHistory.unshift(entry);
  if (state.shellHistory.length > 500) state.shellHistory = state.shellHistory.slice(0, 500);
  persistShellHistory();
}

function openShellHistory() {
  state.section = "snippets";
  state.shellHistorySavingIndex = -1;
  state.detailKind = "shellHistory";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingHost = null;
  state.editingGroup = null;
  state.editingKey = null;
  state.editingSnippet = null;
  state.editingPackage = null;
  state.editingIndex = -1;
  state.editingKeyIndex = -1;
  state.editingSnippetIndex = -1;
  state.keyGenerator = null;
  state.keyGenerating = false;
  closeMenus();
  state.skipFormSync = true;
  render();
}

function saveHistoryAsSnippet(index) {
  const entry = state.shellHistory[index];
  if (!entry) return;
  const labelInput = document.querySelector(`#historyLabel-${index}`);
  const label = labelInput?.value?.trim() || "";
  const snippet = normalizeSnippet({
    name: label,
    script: entry.command,
  });
  state.snippets.unshift(clone(snippet));
  persistSnippets();
  state.shellHistorySavingIndex = -1;
  pushLog("Snippets", `Saved snippet from history: ${entry.command}`);
  setStatus(t("Snippet saved from history"));
}

async function stopExistingShell(nextSessionId = "") {
  const currentSessionId = state.activeShellId;
  if (!currentSessionId || currentSessionId === nextSessionId) return;
  stopShellPolling();
  try {
    await call("stop_shell", { sessionId: currentSessionId, session_id: currentSessionId });
  } catch {
    // 防止前面的会话已经提前关闭导致报错
  }
}

async function openLocalPowershell() {
  const sessionId = "local-terminal";
  await stopExistingShell(sessionId);
  state.activeHost = null;
  state.activeShellId = sessionId;
  state.sessionKind = "local";
  state.shellHealthy = false;
  const termName = isMacOS() ? "Terminal (zsh)" : "PowerShell";
  state.status = t("Opening local {0}...", termName);
  state.view = "localTerminal";
  state.commandInput = "";
  state.connection = null;
  state.metrics = null;
  state.remoteEntries = [];
  closeMenus();
  render({ terminalBottom: true, focusTerminal: true });
  terminalReset(terminalColumns(), terminalRows());
  appendTerminalOutput(`[vps-studio] opening local ${termName}...\r\n`);

  try {
    const summary = await call("start_local_shell", {
      cols: terminalColumns(),
      rows: terminalRows(),
    });
    state.connection = summary;
    state.shellHealthy = true;
    startShellPolling();
    await pollShellOutput();
    pushLog("Terminal", `Opened ${summary.banner || termName}.`);
    setStatus(t("{0} connected at {1}", summary.banner || termName, summary.connectedAt), {
      terminalBottom: true,
      focusTerminal: true,
    });
  } catch (error) {
    state.shellHealthy = false;
    appendTerminalOutput(`[vps-studio] local terminal failed: ${error}\r\n`);
    pushLog("Terminal", `Open local terminal failed: ${error}`);
    setStatus(t("Open local terminal failed: {0}", error), { focusTerminal: true });
  }
}

async function connectHost(host, ignoreKnownHosts = false) {
  if (!host) return;
  const profile = profileForConnection(host);
  if (profile.auth.kind === "keyRef") return setStatus(t("Choose a key from Keychain first"));
  if (profile.auth.kind === "keyData" && !profile.auth.privateKey.trim()) {
    return setStatus(t("Selected Keychain item has no private key"));
  }
  await stopExistingShell(profile.id);
  state.activeHost = profile;
  state.activeShellId = state.activeHost.id;
  state.sessionKind = "ssh";
  state.status = t("Connecting to {0}...", profile.name);
  state.view = "session";
  state.commandInput = "";
  state.metrics = null;
  state.metricsHistory = [];
  state.lastNetDevices = null;
  state.lastMetricsTime = null;
  state.selectedNetInterface = null;
  state.remoteEntries = [];
  state.remotePath = profile.defaultPath || "/root";
  closeMenus();
  render({ terminalBottom: true, focusCommand: true });
  terminalReset(terminalColumns(), terminalRows());
  appendTerminalOutput("[vps-studio] opening interactive shell...\r\n");

  try {
    const cols = terminalColumns();
    const rows = terminalRows();
    const summary = await call("start_shell", {
      profile: state.activeHost,
      cols,
      rows,
      ignoreKnownHosts,
    });
    state.connection = summary;
    state.shellHealthy = true;
    startShellPolling();
    await pollShellOutput();
    pushLog("SSH", `Connected to ${profile.username}@${profile.host}:${profile.port}.`, profile);
    const storedHost = state.hosts.find((h) => h.id === host.id);
    if (storedHost) {
      storedHost.lastConnected = Date.now();
      saveHosts();
    }
    setStatus(t("Connected at {0}", summary.connectedAt), { terminalBottom: true, focusTerminal: true });
    refreshMetrics();
    refreshSftp(state.remotePath);
  } catch (error) {
    if (typeof error === "string" && error.startsWith("UNTRUSTED_HOST:")) {
      const fingerprint = error.substring("UNTRUSTED_HOST:".length);
      state.untrustedHostPrompt = { host: profile, fingerprint };
      render();
      return;
    }
    appendTerminalOutput(`[vps-studio] connection failed: ${error}\r\n`);
    pushLog("SSH", `Connection failed: ${error}`, profile);
    setStatus(t("Connection failed: {0}", error), { terminalBottom: true, focusCommand: true });
  }
}

async function reconnectShell(reason = "") {
  if (state.sessionKind !== "ssh" || !state.activeHost || shellReconnecting) return false;
  shellReconnecting = true;
  const host = state.activeHost;
  state.status = reason ? t("Reconnecting shell: {0}", reason) : t("Reconnecting shell...");
  appendTerminalOutput(`\n[vps-studio] reconnecting interactive shell...\n`);
  try {
    await call("start_shell", {
      profile: host,
      cols: terminalColumns(),
      rows: terminalRows(),
    });
    state.activeShellId = host.id;
    startShellPolling();
    await pollShellOutput();
    state.status = t("Interactive shell reconnected");
    pushLog("SSH", "Interactive shell reconnected.", host);
    render({ terminalBottom: true, focusTerminal: true });
    return true;
  } catch (error) {
    state.status = t("Reconnect failed: {0}", error);
    pushLog("SSH", `Reconnect failed: ${error}`, host);
    render({ terminalBottom: true, focusTerminal: true });
    return false;
  } finally {
    shellReconnecting = false;
  }
}

async function disconnect() {
  const sessionId = state.activeShellId;
  const wasLocal = state.sessionKind === "local";
  stopShellPolling();
  state.activeShellId = null;
  state.sessionKind = null;
  state.shellHealthy = false;
  if (sessionId) {
    try {
      await call("stop_shell", { sessionId, session_id: sessionId });
    } catch {
      // 远端可能已经断开，捕获异常避免崩溃
    }
  }
  pushLog(wasLocal ? "Terminal" : "SSH", wasLocal ? "Closed local terminal." : t("Disconnected") + ".");
  state.view = "dashboard";
  state.activeHost = null;
  state.connection = null;
  state.metrics = null;
  state.remoteEntries = [];
  state.terminal = "";
  terminalReset();
  state.commandInput = "";
  setStatus(wasLocal ? t("Local terminal closed") : t("Disconnected"));
}

function appendTerminal(text) {
  terminalWrite(text);
  const active = document.activeElement;
  const typing = active?.matches?.("input, textarea, select, [contenteditable]") || active?.closest?.(".app-dialog");
  if (!typing) xterm?.focus();
}

function appendTerminalOutput(text) {
  if (String(text || "").includes("[ssh channel closed]")) {
    state.shellHealthy = false;
    state.status = t("SSH channel closed");
    render({ focusTerminal: true });
  }
  terminalWrite(text);
  if (state.sessionKind === "local" && String(text || "").includes("[process exited]")) {
    state.shellHealthy = false;
    setStatus(t("Local terminal closed"));
  }
}

function startShellPolling() {
  stopShellPolling();
  shellOutputPoller = window.setInterval(pollShellOutput, 140);
}

function stopShellPolling() {
  if (shellOutputPoller !== null) {
    window.clearInterval(shellOutputPoller);
    shellOutputPoller = null;
  }
  shellOutputPolling = false;
}

async function pollShellOutput() {
  if (!state.activeShellId || shellOutputPolling) return;
  shellOutputPolling = true;
  const sessionId = state.activeShellId;
  try {
    const text = await call("read_shell", { sessionId, session_id: sessionId });
    if (sessionId === state.activeShellId && text) appendTerminalOutput(text);
  } catch (error) {
    if (sessionId === state.activeShellId) {
      state.shellHealthy = false;
      pushLog(state.sessionKind === "local" ? "Terminal" : "SSH", `Read shell output failed: ${error}`, state.activeHost);
    }
  } finally {
    shellOutputPolling = false;
  }
}

function setupTerminalEvents() {
  if (!listen || terminalEventsRegistered) return;
  terminalEventsRegistered = true;
  Promise.resolve(
    listen("ssh-output", (event) => {
      const payload = event.payload || {};
      if (payload.sessionId && payload.sessionId !== state.activeShellId) return;
      appendTerminalOutput(payload.data || "");
    }),
  ).catch((error) => {
    terminalEventsRegistered = false;
    pushLog("App", `Terminal event listener failed: ${error}`);
    state.status = t("Terminal listener failed: {0}", error);
    render();
  });
}

async function sendShellInput(data) {
  if (!state.activeShellId || !data) return;
  const inputData = normalizeShellInput(data);
  try {
    await call("write_shell", {
      sessionId: state.activeShellId,
      session_id: state.activeShellId,
      data: inputData,
    });
    state.shellHealthy = true;
  } catch (error) {
    state.shellHealthy = false;
    const logKind = state.sessionKind === "local" ? "Terminal" : "SSH";
    pushLog(logKind, `Send failed: ${error}`, state.activeHost);
    const reconnected = state.sessionKind === "ssh" ? await reconnectShell(String(error)) : false;
    if (reconnected) {
      try {
        await call("write_shell", {
          sessionId: state.activeShellId,
          session_id: state.activeShellId,
          data: inputData,
        });
        state.shellHealthy = true;
        return;
      } catch (retryError) {
        pushLog("SSH", `Retry send failed: ${retryError}`, state.activeHost);
      }
    }
    setStatus(t("Send failed: {0}", error), { focusTerminal: true });
  }
}

function normalizeShellInput(data) {
  return data;
}

function handleTerminalData(data) {
  sendShellInput(data);
}

function createTerminalState(cols = 120, rows = 32) {
  return {
    cols,
    rows,
    screen: Array.from({ length: rows }, () => blankLine(cols)),
    scrollback: [],
    cursorRow: 0,
    cursorCol: 0,
    savedRow: 0,
    savedCol: 0,
    cursorVisible: true,
    scrollTop: 0,
    scrollBottom: rows - 1,
    originMode: false,
    applicationCursor: false,
    wraparound: true,
    clearOnNextPrintable: false,
    alt: false,
    main: null,
    pending: "",
  };
}

function blankLine(cols) {
  return Array.from({ length: cols }, () => " ");
}

function isMacOS() {
  return (
    typeof navigator !== "undefined" &&
    (navigator.userAgent.includes("Mac") || (navigator.platform && navigator.platform.toUpperCase().includes("MAC")))
  );
}

function isWindows() {
  return typeof navigator !== "undefined" && /Windows/i.test(navigator.userAgent);
}

// Keep the shell's idea of the terminal size in sync (local PTY or SSH channel),
// so full-screen programs like vim or top use the whole pane.
let resizeShellTimer = null;
function scheduleShellResize(cols, rows) {
  clearTimeout(resizeShellTimer);
  resizeShellTimer = setTimeout(() => {
    if (!state.activeShellId || !invoke) return;
    invoke("resize_shell", { sessionId: state.activeShellId, cols, rows }).catch(() => {});
  }, 80);
}

function ensureXterm() {
  if (xterm || !window.Terminal || !window.FitAddon?.FitAddon) return xterm;
  const isMac = isMacOS();
  xterm = new window.Terminal({
    cursorBlink: true,
    convertEol: false,
    fontFamily: isMac ? '"SF Mono", Menlo, Monaco, monospace' : '"Cascadia Code", Consolas, monospace',
    fontSize: 16,
    fontWeight: 700,
    lineHeight: 1.1,
    scrollback: 8000,
    theme: {
      background: "#000000",
      foreground: "#ffffff",
      cursor: "#dce8ff",
      selectionBackground: "#32466c",
      black: "#000000",
      red: "#ff5f67",
      green: "#5af78e",
      yellow: "#f3f99d",
      blue: "#57c7ff",
      magenta: "#ff6ac1",
      cyan: "#9aedfe",
      white: "#f1f1f0",
      brightBlack: "#686868",
      brightRed: "#ff5f67",
      brightGreen: "#5af78e",
      brightYellow: "#f3f99d",
      brightBlue: "#57c7ff",
      brightMagenta: "#ff6ac1",
      brightCyan: "#9aedfe",
      brightWhite: "#ffffff",
    },
  });
  xtermFit = new window.FitAddon.FitAddon();
  xterm.loadAddon(xtermFit);
  xtermDataDisposable = xterm.onData((data) => handleTerminalData(data));
  xterm.onResize(({ cols, rows }) => scheduleShellResize(cols, rows));
  return xterm;
}

function mountXterm(focus = false) {
  const pane = document.querySelector("#terminalPane");
  const terminal = ensureXterm();
  if (!pane || !terminal) return;
  if (!terminal.element) {
    pane.replaceChildren();
    terminal.open(pane);
    bindXtermClipboard(terminal);
  } else if (terminal.element.parentElement !== pane) {
    pane.replaceChildren();
    pane.appendChild(terminal.element);
  }
  fitXterm();
  if (focus) terminal.focus();
  if (xtermResizeObserver) xtermResizeObserver.disconnect();
  xtermResizeObserver = new ResizeObserver(() => fitXterm());
  xtermResizeObserver.observe(pane);
}

// Termius-style clipboard: releasing a selection copies it, right click pastes.
function bindXtermClipboard(terminal) {
  const element = terminal.element;
  element.addEventListener("mouseup", (event) => {
    if (event.button !== 0) return;
    // Let xterm finish updating the selection (double/triple click) first.
    setTimeout(() => {
      const text = terminal.hasSelection() ? terminal.getSelection() : "";
      if (text) writeClipboardText(text);
    }, 0);
  });
  element.addEventListener("contextmenu", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const text = await readClipboardText();
    if (text) terminal.paste(text);
    terminal.focus();
  });
}

async function writeClipboardText(text) {
  try {
    if (invoke) await invoke("write_clipboard_text", { text });
    else await navigator.clipboard.writeText(text);
  } catch {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      setStatus(t("Copy failed"));
    }
  }
}

async function readClipboardText() {
  try {
    if (invoke) return await invoke("read_clipboard_text");
    return await navigator.clipboard.readText();
  } catch {
    try {
      return await navigator.clipboard.readText();
    } catch {
      return "";
    }
  }
}

function fitXterm() {
  if (!xterm || !xtermFit || !xterm.element) return;
  try {
    xtermFit.fit();
  } catch {
    // 终端重新挂载时可能会计算失败，暂时忽略
  }
}

function terminalReset(cols = terminalColumns(), rows = terminalRows()) {
  ensureXterm();
  if (xterm) {
    if (xterm.cols !== cols || xterm.rows !== rows) xterm.resize(cols, rows);
    xterm.reset();
    xterm.clear();
  }
  state.term = null;
  state.terminal = "";
  // Tell xterm when it talks to Windows ConPTY so line wrapping and reflow
  // match what ConPTY sends; SSH sessions talk to a Unix PTY.
  if (xterm) xterm.options.windowsPty = state.sessionKind === "local" && isWindows() ? { backend: "conpty" } : {};
}

function ensureTerminal() {
  if (!state.term) terminalReset();
  return state.term;
}

function terminalWrite(text) {
  if (ensureXterm()) {
    xterm.write(String(text || ""));
    state.terminal += String(text || "");
    if (state.terminal.length > 200000) state.terminal = state.terminal.slice(-100000);
    return;
  }
  const term = ensureTerminal();
  let input = term.pending + String(text || "");
  term.pending = "";

  for (let index = 0; index < input.length; ) {
    const ch = input[index];
    if (ch === "\x1b") {
      const consumed = consumeEscape(input, index);
      if (consumed === 0) {
        term.pending = input.slice(index);
        break;
      }
      index += consumed;
      continue;
    }

    if (ch === "\n") {
      term.clearOnNextPrintable = false;
      terminalLineFeed();
    } else if (ch === "\r") {
      term.cursorCol = 0;
      term.clearOnNextPrintable = !term.alt;
    } else if (ch === "\b" || ch === "\x7f") {
      term.cursorCol = Math.max(0, term.cursorCol - 1);
    } else if (ch === "\t") {
      term.cursorCol = Math.min(term.cols - 1, term.cursorCol + (8 - (term.cursorCol % 8)));
    } else if (ch >= " " && ch !== "\x7f") {
      terminalPutChar(ch);
    }
    index += 1;
  }

  state.terminal = terminalPlainText();
}

function consumeEscape(input, start) {
  const term = ensureTerminal();
  if (start + 1 >= input.length) return 0;
  const next = input[start + 1];

  if (next === "[") {
    let end = start + 2;
    while (end < input.length && !/[\x40-\x7e]/.test(input[end])) end += 1;
    if (end >= input.length) return 0;
    handleCsi(input.slice(start + 2, end), input[end]);
    return end - start + 1;
  }

  if (next === "]") {
    let end = start + 2;
    while (end < input.length) {
      if (input[end] === "\x07") return end - start + 1;
      if (input[end] === "\x1b" && input[end + 1] === "\\") return end - start + 2;
      end += 1;
    }
    return 0;
  }

  if (next === "(" || next === ")") return start + 2 < input.length ? 3 : 0;
  if (next === "7") {
    terminalSaveCursor();
    return 2;
  }
  if (next === "8") {
    terminalRestoreCursor();
    return 2;
  }
  if (next === "c") {
    terminalReset(term.cols, term.rows);
    return 2;
  }
  if (next === "D") {
    terminalLineFeed();
    return 2;
  }
  if (next === "M") {
    terminalReverseLineFeed();
    return 2;
  }
  if (next === "E") {
    term.cursorCol = 0;
    terminalLineFeed();
    return 2;
  }
  return 2;
}

function handleCsi(sequence, final) {
  const term = ensureTerminal();
  const privateMode = sequence.startsWith("?");
  const clean = privateMode ? sequence.slice(1) : sequence;
  const params = clean
    .split(";")
    .map((part) => (part.length ? Number(part.replace(/[^0-9]/g, "")) || 0 : 0));
  const value = (index, fallback) => params[index] || fallback;

  switch (final) {
    case "A":
      term.cursorRow = clamp(term.cursorRow - value(0, 1), 0, term.rows - 1);
      break;
    case "B":
      term.cursorRow = clamp(term.cursorRow + value(0, 1), 0, term.rows - 1);
      break;
    case "C":
      term.cursorCol = clamp(term.cursorCol + value(0, 1), 0, term.cols - 1);
      break;
    case "D":
      term.cursorCol = clamp(term.cursorCol - value(0, 1), 0, term.cols - 1);
      break;
    case "E":
      term.cursorRow = clamp(term.cursorRow + value(0, 1), 0, term.rows - 1);
      term.cursorCol = 0;
      break;
    case "F":
      term.cursorRow = clamp(term.cursorRow - value(0, 1), 0, term.rows - 1);
      term.cursorCol = 0;
      break;
    case "G":
      term.cursorCol = clamp(value(0, 1) - 1, 0, term.cols - 1);
      break;
    case "H":
    case "f":
      term.cursorRow = cursorAddressRow(value(0, 1));
      term.cursorCol = clamp(value(1, 1) - 1, 0, term.cols - 1);
      break;
    case "d":
      term.cursorRow = cursorAddressRow(value(0, 1));
      break;
    case "J":
      terminalEraseDisplay(value(0, 0));
      break;
    case "K":
      terminalEraseLine(value(0, 0));
      break;
    case "L":
      terminalInsertLines(value(0, 1));
      break;
    case "M":
      terminalDeleteLines(value(0, 1));
      break;
    case "P":
      terminalDeleteChars(value(0, 1));
      break;
    case "X":
      terminalEraseChars(value(0, 1));
      break;
    case "@":
      terminalInsertChars(value(0, 1));
      break;
    case "b":
      terminalRepeatLastChar(value(0, 1));
      break;
    case "S":
      terminalScrollUp(value(0, 1));
      break;
    case "T":
      terminalScrollDown(value(0, 1));
      break;
    case "s":
      terminalSaveCursor();
      break;
    case "u":
      terminalRestoreCursor();
      break;
    case "r":
      terminalSetScrollRegion(value(0, 1), value(1, term.rows));
      break;
    case "h":
      if (privateMode) handlePrivateMode(params, true);
      break;
    case "l":
      if (privateMode) handlePrivateMode(params, false);
      break;
    case "m":
      break;
    case "q":
      break;
  }
}

function handlePrivateMode(params, enabled) {
  const term = ensureTerminal();
  for (const param of params) {
    if (param === 1) term.applicationCursor = enabled;
    if (param === 7) term.wraparound = enabled;
    if (param === 25) term.cursorVisible = enabled;
    if (param === 6) {
      term.originMode = enabled;
      term.cursorRow = enabled ? term.scrollTop : 0;
      term.cursorCol = 0;
    }
    if (param === 47 || param === 1047 || param === 1049) {
      if (enabled && !term.alt) {
        term.main = {
          screen: term.screen.map((line) => [...line]),
          scrollback: [...term.scrollback],
          cursorRow: term.cursorRow,
          cursorCol: term.cursorCol,
          scrollTop: term.scrollTop,
          scrollBottom: term.scrollBottom,
          originMode: term.originMode,
          applicationCursor: term.applicationCursor,
          wraparound: term.wraparound,
        };
        term.alt = true;
        term.screen = Array.from({ length: term.rows }, () => blankLine(term.cols));
        term.scrollback = [];
        term.cursorRow = 0;
        term.cursorCol = 0;
        term.scrollTop = 0;
        term.scrollBottom = term.rows - 1;
        term.originMode = false;
        term.wraparound = true;
        term.clearOnNextPrintable = false;
      } else if (!enabled && term.alt && term.main) {
        term.screen = term.main.screen;
        term.scrollback = term.main.scrollback;
        term.cursorRow = term.main.cursorRow;
        term.cursorCol = term.main.cursorCol;
        term.scrollTop = term.main.scrollTop;
        term.scrollBottom = term.main.scrollBottom;
        term.originMode = term.main.originMode;
        term.applicationCursor = term.main.applicationCursor;
        term.wraparound = term.main.wraparound;
        term.main = null;
        term.alt = false;
        term.clearOnNextPrintable = false;
      }
    }
  }
}

function terminalPutChar(ch) {
  const term = ensureTerminal();
  if (!term.alt && term.clearOnNextPrintable) {
    terminalEraseLine(0);
    term.clearOnNextPrintable = false;
  }
  term.screen[term.cursorRow][term.cursorCol] = ch;
  if (term.cursorCol >= term.cols - 1) {
    if (!term.wraparound) return;
    term.cursorCol = 0;
    terminalLineFeed();
  } else {
    term.cursorCol += 1;
  }
}

function terminalLineFeed() {
  const term = ensureTerminal();
  if (term.cursorRow === term.scrollBottom) {
    terminalScrollRegionUp(1);
  } else {
    term.cursorRow = clamp(term.cursorRow + 1, 0, term.rows - 1);
  }
}

function terminalReverseLineFeed() {
  const term = ensureTerminal();
  if (term.cursorRow === term.scrollTop) {
    terminalScrollRegionDown(1);
  } else {
    term.cursorRow = clamp(term.cursorRow - 1, 0, term.rows - 1);
  }
}

function terminalEraseDisplay(mode) {
  const term = ensureTerminal();
  if (mode === 2 || mode === 3) {
    term.screen = Array.from({ length: term.rows }, () => blankLine(term.cols));
    if (mode === 3) term.scrollback = [];
    return;
  }
  if (mode === 1) {
    for (let row = 0; row < term.cursorRow; row += 1) term.screen[row] = blankLine(term.cols);
    term.screen[term.cursorRow].fill(" ", 0, term.cursorCol + 1);
    return;
  }
  term.screen[term.cursorRow].fill(" ", term.cursorCol);
  for (let row = term.cursorRow + 1; row < term.rows; row += 1) term.screen[row] = blankLine(term.cols);
}

function terminalEraseLine(mode) {
  const term = ensureTerminal();
  if (mode === 2) {
    term.screen[term.cursorRow] = blankLine(term.cols);
  } else if (mode === 1) {
    term.screen[term.cursorRow].fill(" ", 0, term.cursorCol + 1);
  } else {
    term.screen[term.cursorRow].fill(" ", term.cursorCol);
  }
}

function terminalInsertLines(count) {
  const term = ensureTerminal();
  if (term.cursorRow < term.scrollTop || term.cursorRow > term.scrollBottom) return;
  const row = term.cursorRow;
  for (let i = 0; i < count; i += 1) {
    term.screen.splice(row, 0, blankLine(term.cols));
    term.screen.splice(term.scrollBottom + 1, 1);
  }
}

function terminalDeleteLines(count) {
  const term = ensureTerminal();
  if (term.cursorRow < term.scrollTop || term.cursorRow > term.scrollBottom) return;
  const row = term.cursorRow;
  for (let i = 0; i < count; i += 1) {
    term.screen.splice(row, 1);
    term.screen.splice(term.scrollBottom, 0, blankLine(term.cols));
  }
}

function terminalInsertChars(count) {
  const term = ensureTerminal();
  const line = term.screen[term.cursorRow];
  line.splice(term.cursorCol, 0, ...Array.from({ length: count }, () => " "));
  line.length = term.cols;
}

function terminalDeleteChars(count) {
  const term = ensureTerminal();
  const line = term.screen[term.cursorRow];
  line.splice(term.cursorCol, count);
  while (line.length < term.cols) line.push(" ");
}

function terminalEraseChars(count) {
  const term = ensureTerminal();
  const line = term.screen[term.cursorRow];
  line.fill(" ", term.cursorCol, Math.min(term.cols, term.cursorCol + count));
}

function terminalRepeatLastChar(count) {
  const term = ensureTerminal();
  const col = Math.max(0, term.cursorCol - 1);
  const ch = term.screen[term.cursorRow][col] || " ";
  for (let i = 0; i < count; i += 1) terminalPutChar(ch);
}

function terminalScrollUp(count) {
  terminalScrollRegionUp(count);
}

function terminalScrollDown(count) {
  terminalScrollRegionDown(count);
}

function terminalScrollRegionUp(count) {
  const term = ensureTerminal();
  for (let i = 0; i < count; i += 1) {
    const line = term.screen.splice(term.scrollTop, 1)[0];
    if (!term.alt && term.scrollTop === 0 && term.scrollBottom === term.rows - 1) {
      term.scrollback.push(lineToString(line));
      if (term.scrollback.length > 2000) term.scrollback.shift();
    }
    term.screen.splice(term.scrollBottom, 0, blankLine(term.cols));
  }
}

function terminalScrollRegionDown(count) {
  const term = ensureTerminal();
  for (let i = 0; i < count; i += 1) {
    term.screen.splice(term.scrollBottom, 1);
    term.screen.splice(term.scrollTop, 0, blankLine(term.cols));
  }
}

function terminalSaveCursor() {
  const term = ensureTerminal();
  term.savedRow = term.cursorRow;
  term.savedCol = term.cursorCol;
}

function terminalRestoreCursor() {
  const term = ensureTerminal();
  term.cursorRow = clamp(term.savedRow, 0, term.rows - 1);
  term.cursorCol = clamp(term.savedCol, 0, term.cols - 1);
}

function terminalSetScrollRegion(top, bottom) {
  const term = ensureTerminal();
  const nextTop = clamp(top - 1, 0, term.rows - 1);
  const nextBottom = clamp(bottom - 1, 0, term.rows - 1);
  if (nextBottom <= nextTop) {
    term.scrollTop = 0;
    term.scrollBottom = term.rows - 1;
  } else {
    term.scrollTop = nextTop;
    term.scrollBottom = nextBottom;
  }
  term.cursorRow = term.originMode ? term.scrollTop : 0;
  term.cursorCol = 0;
}

function cursorAddressRow(row) {
  const term = ensureTerminal();
  const zeroBased = row - 1;
  if (term.originMode) {
    return clamp(term.scrollTop + zeroBased, term.scrollTop, term.scrollBottom);
  }
  return clamp(zeroBased, 0, term.rows - 1);
}

function terminalPlainText() {
  return terminalLines().join("\n");
}

function terminalLines() {
  const term = ensureTerminal();
  const screen = term.screen.map(lineToString);
  return term.alt ? screen : [...term.scrollback, ...screen];
}

function terminalCursorLineIndex() {
  const term = ensureTerminal();
  return term.alt ? term.cursorRow : term.scrollback.length + term.cursorRow;
}

function lineToString(line) {
  return line.join("").replace(/\s+$/g, "");
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

async function runTerminalCommand() {
  const command = state.commandInput.trim();
  if (!command || !state.activeShellId) return;
  state.commandInput = "";
  const host = state.activeHost || { name: "Local Terminal", username: "local" };
  pushLog("Command", command, host);
  recordShellHistory(command);
  render({ terminalBottom: true, focusTerminal: true });
  await sendShellInput(`${command}\r`);
}

async function refreshMetrics() {
  if (!state.activeHost) return;
  try {
    const metrics = await call("collect_metrics", { profile: state.activeHost });
    if (!state.activeHost) return;
    
    state.metrics = metrics;

    if (metrics && metrics.os && state.activeHost.os !== metrics.os) {
      state.activeHost.os = metrics.os;
      const hostInList = state.hosts.find(h => h.id === state.activeHost.id);
      if (hostInList) {
        hostInList.os = metrics.os;
        saveHosts();
      }
    }

    const now = Date.now();
    let netSpeeds = {};
    if (state.lastNetDevices && state.lastMetricsTime) {
      const dt = (now - state.lastMetricsTime) / 1000;
      if (dt > 0) {
        for (const dev of metrics.netDevices) {
          const last = state.lastNetDevices.find((d) => d.name === dev.name);
          if (last) {
            let rxDiff = dev.rxBytes - last.rxBytes;
            let txDiff = dev.txBytes - last.txBytes;
            if (rxDiff < 0) rxDiff = 0;
            if (txDiff < 0) txDiff = 0;
            netSpeeds[dev.name] = {
              rxSpeed: rxDiff / dt,
              txSpeed: txDiff / dt,
            };
          }
        }
      }
    }
    state.lastNetDevices = metrics.netDevices;
    state.lastMetricsTime = now;

    if (!state.metricsHistory) state.metricsHistory = [];
    state.metricsHistory.push({
      time: now,
      latency: metrics.latencyMs || 0,
      netSpeeds,
    });

    if (state.metricsHistory.length > 60) {
      state.metricsHistory.shift();
    }

    refreshMonitorPanel();
  } catch (error) {
    state.status = t("Metrics failed: {0}", error);
    render();
  }
}

// Repaint only the session monitor sidebar. A full render() rebuilds the SFTP
// table and resets its scroll position, which stutters an in-progress scroll.
function refreshMonitorPanel() {
  const monitor = state.view === "session" ? document.querySelector(".session > .monitor") : null;
  if (!monitor) {
    render();
    return;
  }
  monitor.innerHTML = renderMonitor();
  syncComboAfterRender();
}

async function refreshSftp(path = state.remotePath) {
  if (!state.activeHost) return;
  try {
    const dir = await call("list_remote_dir", { profile: state.activeHost, path });
    const samePath = dir.path === state.remotePath;
    state.remotePath = dir.path;
    state.remoteEntries = dir.entries || [];
    const present = new Set(state.remoteEntries.map((entry) => entry.path));
    state.sftpSelected = samePath ? state.sftpSelected.filter((item) => present.has(item)) : [];
    if (!samePath || !present.has(state.sftpAnchor)) state.sftpAnchor = null;
    render();
  } catch (error) {
    state.status = t("SFTP failed: {0}", error);
    render();
  }
}

async function openRemote(entry, { openWith = false } = {}) {
  if (entry.isDir) {
    await refreshSftp(entry.path);
    return;
  }
  try {
    const watched = await call("open_remote_file", {
      profile: state.activeHost,
      remotePath: entry.path,
      openWith,
    });
    state.watchedFiles = state.watchedFiles.filter((file) => file.remotePath !== watched.remotePath);
    state.watchedFiles.push(watched);
    pushLog("SFTP", `Opened ${entry.path}.`, state.activeHost);
    setStatus(t("Opened {0}", entry.name));
  } catch (error) {
    setStatus(t("Open failed: {0}", error));
  }
}

async function uploadWatched(file) {
  try {
    await call("upload_edited_file", {
      profile: state.activeHost,
      remotePath: file.remotePath,
      remote_path: file.remotePath,
      localPath: file.localPath,
      local_path: file.localPath,
    });
    file.dirty = false;
    file.originalModifiedMs = file.lastSeenModifiedMs;
    pushLog("SFTP", `Uploaded ${file.remotePath}.`, state.activeHost);
    setStatus(t("Uploaded {0}", file.remotePath));
    await refreshSftp();
  } catch (error) {
    setStatus(t("Upload failed: {0}", error));
  }
}

/* --------------------------------------------------------------------------
   SFTP file browser: Termius-style selection, context menus and dialogs.
   Menu and dialogs live on <body> so periodic render() calls never close
   them or wipe what the user typed; selection only toggles row classes so
   the table's scroll position is never reset.
   -------------------------------------------------------------------------- */
let sftpMenuEl = null;
let sftpDialogEl = null;
let sftpDialog = null;

function sftpEntry(path) {
  return state.remoteEntries.find((entry) => entry.path === path) || null;
}

function sftpSelectedEntries() {
  return state.sftpSelected.map(sftpEntry).filter(Boolean);
}

function sftpVisibleEntries() {
  const q = state.sftpFilter.trim().toLowerCase();
  return state.remoteEntries.filter((entry) => !q || entry.name.toLowerCase().includes(q));
}

function applySftpSelection() {
  const selected = new Set(state.sftpSelected);
  document.querySelectorAll(".table-wrap tr[data-sftp-path]").forEach((row) => {
    row.classList.toggle("selected", selected.has(row.dataset.sftpPath));
  });
}

function selectSftpRow(path, { toggle = false, range = false } = {}) {
  if (range && state.sftpAnchor) {
    const paths = sftpVisibleEntries().map((entry) => entry.path);
    const from = paths.indexOf(state.sftpAnchor);
    const to = paths.indexOf(path);
    if (from >= 0 && to >= 0) {
      const [start, end] = from < to ? [from, to] : [to, from];
      const span = paths.slice(start, end + 1);
      state.sftpSelected = toggle ? [...new Set([...state.sftpSelected, ...span])] : span;
      applySftpSelection();
      return;
    }
  }
  if (toggle) {
    state.sftpSelected = state.sftpSelected.includes(path)
      ? state.sftpSelected.filter((item) => item !== path)
      : [...state.sftpSelected, path];
  } else {
    state.sftpSelected = [path];
  }
  state.sftpAnchor = path;
  applySftpSelection();
}

function clearSftpSelection() {
  if (!state.sftpSelected.length) return;
  state.sftpSelected = [];
  state.sftpAnchor = null;
  applySftpSelection();
}

/* ---------- context menu ---------- */

function sftpMenuIcon(name) {
  const paths = {
    open: '<path d="M14 3h7v7"/><path d="M10 14 21 3"/><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/>',
    openWith: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M17.5 14v7M14 17.5h7"/>',
    rename: '<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>',
    delete: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>',
    newFolder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><path d="M12 11v6M9 14h6"/>',
    permissions: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name]}</svg>`;
}

function openSftpMenu(x, y, target) {
  closeSftpMenu();
  const selected = sftpSelectedEntries();
  const items = [];
  const item = (cmd, icon, label, danger = false) => ({ cmd, icon, label, danger });
  if (target && selected.length > 1) {
    items.push(item("delete", "delete", t("Delete {0} items", selected.length), true));
  } else if (target) {
    const isFolder = target.isDir && !target.isLink;
    if (!isFolder) {
      items.push(item("open", "open", t("Open")));
      items.push(item("openWith", "openWith", t("Open with...")));
    }
    items.push(item("rename", "rename", t("Rename")));
    items.push(item("delete", "delete", t("Delete"), true));
  }
  items.push(item("refresh", "refresh", t("Refresh")));
  items.push(item("newFolder", "newFolder", t("New Folder")));
  if (target && selected.length <= 1) items.push(item("permissions", "permissions", t("Edit Permissions")));

  sftpMenuEl = document.createElement("div");
  sftpMenuEl.className = "context-menu sftp-menu";
  sftpMenuEl.innerHTML = items
    .map((entry) => `<button class="${entry.danger ? "danger-text" : ""}" data-sftp-cmd="${entry.cmd}">${sftpMenuIcon(entry.icon)} <span>${escapeHtml(entry.label)}</span></button>`)
    .join("");
  sftpMenuEl.addEventListener("mousedown", (event) => event.stopPropagation());
  sftpMenuEl.addEventListener("click", (event) => {
    event.stopPropagation();
    const button = event.target.closest("[data-sftp-cmd]");
    if (!button) return;
    closeSftpMenu();
    runSftpCommand(button.dataset.sftpCmd, target);
  });
  document.body.appendChild(sftpMenuEl);
  const rect = sftpMenuEl.getBoundingClientRect();
  sftpMenuEl.style.left = `${Math.max(8, Math.min(x, window.innerWidth - rect.width - 8))}px`;
  sftpMenuEl.style.top = `${Math.max(8, Math.min(y, window.innerHeight - rect.height - 8))}px`;
}

function closeSftpMenu() {
  sftpMenuEl?.remove();
  sftpMenuEl = null;
}

async function runSftpCommand(cmd, target) {
  switch (cmd) {
    case "open":
      return sftpOpen(target);
    case "openWith":
      return sftpOpenWith(target);
    case "rename":
      return sftpRename(target);
    case "delete":
      return sftpDelete(sftpSelectedEntries().length ? sftpSelectedEntries() : [target]);
    case "refresh":
      return refreshSftp();
    case "newFolder":
      return sftpNewFolder();
    case "permissions":
      return sftpEditPermissions(target);
  }
}

/* ---------- commands ---------- */

function sftpLinkError() {
  showSftpError(t("This is a link. Modifying this file may cause unexpected errors."));
}

async function sftpOpen(entry) {
  if (!entry) return;
  if (entry.isDir) return refreshSftp(entry.path); // folders and links to folders
  if (entry.isLink) return sftpLinkError();
  return openRemote(entry);
}

async function sftpOpenWith(entry) {
  if (!entry) return;
  if (entry.isLink && entry.isDir) return showSftpError(t("Symlink is a directory. Cannot open directory with app."));
  if (entry.isLink) return sftpLinkError();
  if (entry.isDir) return showSftpError(t("Cannot open a directory with an app."));
  return openRemote(entry, { openWith: true });
}

function validFileName(name) {
  return name && name !== "." && name !== ".." && !/[\\/]/.test(name);
}

function sftpNewFolder() {
  openSftpDialog({
    kind: "input",
    title: t("New folder"),
    label: t("Folder name"),
    value: "",
    confirmLabel: t("Confirm"),
    onConfirm: async (name) => {
      if (!validFileName(name)) return t("Invalid name");
      try {
        await call("create_remote_folder", { profile: state.activeHost, parent: state.remotePath, name });
        await refreshSftp();
        selectSftpRow(joinPath(state.remotePath, name));
      } catch (error) {
        return t("Create folder failed: {0}", error);
      }
    },
  });
}

function sftpRename(entry) {
  if (!entry) return;
  openSftpDialog({
    kind: "input",
    title: t("Rename"),
    label: t("Name"),
    value: entry.name,
    selectBaseName: !entry.isDir,
    confirmLabel: t("Rename"),
    onConfirm: async (name) => {
      if (name === entry.name) return;
      if (!validFileName(name)) return t("Invalid name");
      const to = joinPath(parentPath(entry.path), name);
      try {
        await call("rename_remote", { profile: state.activeHost, from: entry.path, to });
        state.sftpSelected = [to];
        state.sftpAnchor = to;
        await refreshSftp();
      } catch (error) {
        return t("Rename failed: {0}", error);
      }
    },
  });
}

function sftpEditPermissions(entry) {
  if (!entry) return;
  openSftpDialog({
    kind: "permissions",
    title: t("Edit Permissions"),
    subtitle: entry.name,
    mode: (entry.permissions ?? 0o644) & 0o777,
    confirmLabel: t("Confirm"),
    onConfirm: async (mode) => {
      try {
        await call("chmod_remote", { profile: state.activeHost, remotePath: entry.path, mode });
        await refreshSftp();
      } catch (error) {
        return t("Change permissions failed: {0}", error);
      }
    },
  });
}

async function sftpDelete(entries) {
  entries = entries.filter(Boolean);
  if (!entries.length) return;
  const toItem = (entry) => ({
    type: entry.isDir && !entry.isLink ? "folder" : "file",
    title: entry.name,
    subtitle: entry.path,
  });
  const single = entries.length === 1;
  const asFolder = single && entries[0].isDir && !entries[0].isLink;
  const confirmed = await requestDeleteConfirmation({
    title: single ? (asFolder ? t("Remove folder") : t("Remove file")) : t("Remove {0} items", entries.length),
    message: single
      ? asFolder
        ? t("Are you sure you want to remove this folder and everything in it?")
        : t("Are you sure you want to remove this file?")
      : t("Are you sure you want to remove these items? Folders are removed with everything in them."),
    item: toItem(entries[0]),
    affected: entries.slice(1).map(toItem),
    affectedLabel: t("And these items:"),
  });
  if (!confirmed) return;
  for (const entry of entries) {
    // A link is always removed as a file (unlink), never as its target folder.
    const isDir = entry.isDir && !entry.isLink;
    try {
      await call("delete_remote", { profile: state.activeHost, remotePath: entry.path, isDir });
      pushLog("SFTP", `Deleted ${entry.path}.`, state.activeHost);
    } catch (error) {
      await refreshSftp();
      return showSftpError(t("Delete failed: {0}", error));
    }
  }
  state.sftpSelected = [];
  await refreshSftp();
}

function joinPath(dir, name) {
  return `${String(dir || "/").replace(/\/+$/, "")}/${name}`;
}

/* ---------- dialogs ---------- */

function showSftpError(message) {
  openSftpDialog({ kind: "error", title: t("Error"), message });
}

function openSftpDialog(dialog) {
  closeSftpDialog();
  sftpDialog = { ...dialog, error: "" };
  sftpDialogEl = document.createElement("div");
  sftpDialogEl.className = "delete-dialog-overlay app-dialog";
  sftpDialogEl.addEventListener("mousedown", (event) => {
    if (event.target === sftpDialogEl) closeSftpDialog();
  });
  sftpDialogEl.addEventListener("click", onSftpDialogClick);
  sftpDialogEl.addEventListener("input", onSftpDialogInput);
  sftpDialogEl.addEventListener("change", onSftpDialogInput);
  sftpDialogEl.addEventListener("keydown", (event) => {
    event.stopPropagation();
    if (event.key === "Escape") closeSftpDialog();
    if (event.key === "Enter" && sftpDialog?.kind !== "error") {
      event.preventDefault();
      confirmSftpDialog();
    }
  });
  document.body.appendChild(sftpDialogEl);
  drawSftpDialog();
  const input = sftpDialogEl.querySelector(".md-outlined-field input, .perm-octal");
  if (input) {
    input.focus();
    if (dialog.kind === "input") {
      const dot = dialog.selectBaseName ? input.value.lastIndexOf(".") : -1;
      input.setSelectionRange(0, dot > 0 ? dot : input.value.length);
    }
  } else {
    sftpDialogEl.querySelector(".delete-dialog-close")?.focus();
  }
}

function closeSftpDialog() {
  sftpDialogEl?.remove();
  sftpDialogEl = null;
  sftpDialog = null;
}

const PERM_BITS = [
  ["Owner", 0o400, 0o200, 0o100],
  ["Owner group", 0o040, 0o020, 0o010],
  ["Others", 0o004, 0o002, 0o001],
];

function sftpDialogCanConfirm() {
  if (!sftpDialog || sftpDialog.busy) return false;
  if (sftpDialog.kind === "input") return Boolean(sftpDialog.value.trim());
  return true;
}

function drawSftpDialog() {
  const dialog = sftpDialog;
  if (!dialog || !sftpDialogEl) return;
  let body = "";
  if (dialog.kind === "error") {
    body = `<p class="app-dialog-message">${escapeHtml(dialog.message)}</p>`;
  } else if (dialog.kind === "input") {
    body = `
      <label class="md-outlined-field">
        <input type="text" value="${escapeAttr(dialog.value)}" autocomplete="off" spellcheck="false" placeholder=" " />
        <span class="md-outlined-label">${escapeHtml(dialog.label)} *</span>
      </label>`;
  } else if (dialog.kind === "permissions") {
    body = `
      <div class="perm-subtitle">${escapeHtml(dialog.subtitle)}</div>
      <div class="perm-grid">
        <span></span><span>${t("Read")}</span><span>${t("Write")}</span><span>${t("Execute")}</span>
        ${PERM_BITS.map(([who, ...bits]) => `
          <span class="perm-who">${t(who)}</span>
          ${bits.map((bit) => `<label class="md-checkbox"><input type="checkbox" data-perm-bit="${bit}" ${dialog.mode & bit ? "checked" : ""} /><span></span></label>`).join("")}
        `).join("")}
      </div>
      <label class="md-outlined-field perm-octal-field">
        <input class="perm-octal" type="text" inputmode="numeric" maxlength="3" value="${dialog.mode.toString(8).padStart(3, "0")}" placeholder=" " />
        <span class="md-outlined-label">${t("Octal")}</span>
      </label>`;
  }
  const footer =
    dialog.kind === "error"
      ? ""
      : `<footer class="delete-dialog-footer">
          <button class="btn primary app-dialog-confirm" data-dialog-confirm ${sftpDialogCanConfirm() ? "" : "disabled"}>${escapeHtml(dialog.confirmLabel || t("Confirm"))}</button>
        </footer>`;
  sftpDialogEl.innerHTML = `
    <section class="delete-dialog app-dialog-box" role="dialog" aria-modal="true">
      <header class="delete-dialog-header">
        <h2>${escapeHtml(dialog.title)}</h2>
        <button class="icon-btn delete-dialog-close" data-dialog-close title="${t("Close")}" aria-label="${t("Close")}">${closeIcon()}</button>
      </header>
      <div class="delete-dialog-body">
        ${body}
        ${dialog.error ? `<div class="field-error">${escapeHtml(dialog.error)}</div>` : ""}
      </div>
      ${footer}
    </section>`;
}

function refreshSftpDialogChrome() {
  const confirm = sftpDialogEl?.querySelector("[data-dialog-confirm]");
  if (confirm) confirm.disabled = !sftpDialogCanConfirm();
  const error = sftpDialogEl?.querySelector(".field-error");
  if (error && !sftpDialog.error) error.remove();
}

function onSftpDialogInput(event) {
  if (!sftpDialog) return;
  sftpDialog.error = "";
  if (sftpDialog.kind === "input" && event.target.matches(".md-outlined-field input")) {
    sftpDialog.value = event.target.value;
  } else if (sftpDialog.kind === "permissions") {
    if (event.target.matches("[data-perm-bit]")) {
      const bit = Number(event.target.dataset.permBit);
      sftpDialog.mode = event.target.checked ? sftpDialog.mode | bit : sftpDialog.mode & ~bit;
      sftpDialogEl.querySelector(".perm-octal").value = sftpDialog.mode.toString(8).padStart(3, "0");
    } else if (event.target.matches(".perm-octal")) {
      const text = event.target.value.replace(/[^0-7]/g, "").slice(0, 3);
      if (text !== event.target.value) event.target.value = text;
      if (text.length) {
        sftpDialog.mode = parseInt(text, 8);
        sftpDialogEl.querySelectorAll("[data-perm-bit]").forEach((box) => {
          box.checked = Boolean(sftpDialog.mode & Number(box.dataset.permBit));
        });
      }
    }
  }
  refreshSftpDialogChrome();
}

function onSftpDialogClick(event) {
  if (event.target.closest("[data-dialog-close]")) return closeSftpDialog();
  if (event.target.closest("[data-dialog-confirm]")) confirmSftpDialog();
}

async function confirmSftpDialog() {
  const dialog = sftpDialog;
  if (!dialog?.onConfirm || !sftpDialogCanConfirm()) return;
  dialog.busy = true;
  refreshSftpDialogChrome();
  const value = dialog.kind === "permissions" ? dialog.mode : dialog.value.trim();
  const error = await dialog.onConfirm(value);
  if (sftpDialog !== dialog) return;
  dialog.busy = false;
  if (error) {
    dialog.error = error;
    drawSftpDialog();
    sftpDialogEl.querySelector(".md-outlined-field input")?.focus();
    return;
  }
  closeSftpDialog();
}

/* ---------- event wiring (once, delegated) ---------- */

function bindSftpEvents() {
  document.addEventListener("click", (event) => {
    if (sftpMenuEl && !sftpMenuEl.contains(event.target)) closeSftpMenu();
    const wrap = event.target.closest(".table-wrap");
    if (!wrap) return;
    const row = event.target.closest("tr[data-sftp-path]");
    if (!row) {
      if (!event.target.closest("thead")) clearSftpSelection();
      return;
    }
    selectSftpRow(row.dataset.sftpPath, { toggle: event.ctrlKey || event.metaKey, range: event.shiftKey });
  });

  document.addEventListener("dblclick", (event) => {
    const row = event.target.closest(".table-wrap tr[data-sftp-path]");
    if (!row || event.ctrlKey || event.metaKey || event.shiftKey) return;
    selectSftpRow(row.dataset.sftpPath);
    sftpOpen(sftpEntry(row.dataset.sftpPath));
  });

  document.addEventListener("contextmenu", (event) => {
    const wrap = event.target.closest(".table-wrap");
    if (!wrap) return;
    event.preventDefault();
    const row = event.target.closest("tr[data-sftp-path]");
    if (!row) {
      if (event.target.closest("thead")) return;
      clearSftpSelection();
      openSftpMenu(event.clientX, event.clientY, null);
      return;
    }
    const path = row.dataset.sftpPath;
    if (!state.sftpSelected.includes(path)) selectSftpRow(path);
    openSftpMenu(event.clientX, event.clientY, sftpEntry(path));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && sftpMenuEl) closeSftpMenu();
  });
  window.addEventListener("resize", closeSftpMenu);
  // Not "scroll": render() restores scroll positions and would close the menu.
  document.addEventListener("wheel", (event) => {
    if (sftpMenuEl && !sftpMenuEl.contains(event.target)) closeSftpMenu();
  }, { capture: true, passive: true });
}

/* --------------------------------------------------------------------------
   Drag a host onto a group card, or a snippet onto a package card. The move
   is applied after a 5 second countdown that can be undone (Termius-style).
   -------------------------------------------------------------------------- */
const MOVE_DELAY_SECONDS = 5;
let dragItem = null; // { kind: "host" | "snippet", id }
let pendingMove = null; // { kind, id, to, remaining, timer }
let moveToastEl = null;

function dropTargetFor(element) {
  if (!dragItem || !element?.closest) return null;
  return dragItem.kind === "host"
    ? element.closest(".group-card[data-group]")
    : element.closest(".package-card[data-package-id]");
}

function clearDropHighlight() {
  document.querySelectorAll(".drop-target").forEach((el) => el.classList.remove("drop-target"));
}

function moveAlreadyApplied(kind, id, to) {
  if (kind === "host") {
    const host = state.hosts.find((item) => item.id === id);
    return !host || normalizeGroupPath(host.group || "Default") === normalizeGroupPath(to);
  }
  const snippet = state.snippets.find((item) => item.id === id);
  return !snippet || (snippet.packageId || "") === to;
}

function moveTargetLabel(kind, to) {
  return kind === "host" ? groupLabel(to) : packageLabel(packageById(to));
}

function scheduleMove(kind, id, to) {
  if (pendingMove) commitPendingMove();
  if (moveAlreadyApplied(kind, id, to)) return;
  pendingMove = { kind, id, to, remaining: MOVE_DELAY_SECONDS, timer: null };
  pendingMove.timer = setInterval(() => {
    if (!pendingMove) return;
    pendingMove.remaining -= 1;
    if (pendingMove.remaining <= 0) commitPendingMove();
    else drawMoveToast();
  }, 1000);
  drawMoveToast();
}

async function commitPendingMove() {
  const move = pendingMove;
  if (!move) return;
  clearInterval(move.timer);
  pendingMove = null;
  removeMoveToast();
  if (move.kind === "host") {
    const host = state.hosts.find((item) => item.id === move.id);
    if (!host) return;
    host.group = normalizeGroupPath(move.to);
    render();
    try {
      await saveHosts();
    } catch (error) {
      setStatus(t("Save failed: {0}", error));
      return;
    }
  } else {
    const snippet = state.snippets.find((item) => item.id === move.id);
    if (!snippet || !packageById(move.to)) return;
    snippet.packageId = move.to;
    persistSnippets();
    render();
  }
  setStatus(t("Moved to {0}", moveTargetLabel(move.kind, move.to)));
}

function cancelPendingMove() {
  if (!pendingMove) return;
  clearInterval(pendingMove.timer);
  pendingMove = null;
  removeMoveToast();
}

function drawMoveToast() {
  if (!pendingMove) return;
  if (!moveToastEl) {
    moveToastEl = document.createElement("div");
    moveToastEl.className = "move-toast";
    moveToastEl.setAttribute("role", "status");
    moveToastEl.addEventListener("click", (event) => {
      if (event.target.closest("[data-move-undo]")) cancelPendingMove();
      else if (event.target.closest("[data-move-now]")) commitPendingMove();
    });
    document.body.appendChild(moveToastEl);
  }
  const { kind, to, remaining } = pendingMove;
  const label = moveTargetLabel(kind, to);
  const message = kind === "host" ? t("Moving 1 host to {0}", label) : t("Moving 1 snippet to {0}", label);
  // Only the number changes each second; the ring animates on its own.
  if (moveToastEl.dataset.ready) {
    moveToastEl.querySelector(".move-toast-number").textContent = String(remaining);
    return;
  }
  moveToastEl.dataset.ready = "1";
  moveToastEl.innerHTML = `
    <div class="move-toast-count" aria-hidden="true">
      <svg viewBox="0 0 40 40"><circle class="track" cx="20" cy="20" r="17"/><circle class="ring" cx="20" cy="20" r="17" style="animation-duration:${MOVE_DELAY_SECONDS}s"/></svg>
      <span class="move-toast-number">${remaining}</span>
    </div>
    <div class="move-toast-body">
      <div class="move-toast-text">${escapeHtml(message)}</div>
      <button class="btn move-toast-undo" data-move-undo>${t("Undo")}</button>
    </div>
    <button class="icon-btn quiet move-toast-close" data-move-now title="${t("Move now")}" aria-label="${t("Move now")}">${closeIcon()}</button>
  `;
}

function removeMoveToast() {
  moveToastEl?.remove();
  moveToastEl = null;
}

function bindDragAndDrop() {
  document.addEventListener("dragstart", (event) => {
    const host = event.target.closest?.(".host-card[data-host-id]");
    const snippet = event.target.closest?.(".snippet-card[data-snippet-id]");
    const card = host || snippet;
    if (!card) return;
    dragItem = host ? { kind: "host", id: host.dataset.hostId } : { kind: "snippet", id: snippet.dataset.snippetId };
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", dragItem.id);
    card.classList.add("dragging");
    document.body.classList.add(`dragging-${dragItem.kind}`);
  });

  document.addEventListener("dragover", (event) => {
    const target = dropTargetFor(event.target);
    if (!target) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    if (!target.classList.contains("drop-target")) {
      clearDropHighlight();
      target.classList.add("drop-target");
    }
  });

  document.addEventListener("dragleave", (event) => {
    const target = dropTargetFor(event.target);
    if (target && !target.contains(event.relatedTarget)) target.classList.remove("drop-target");
  });

  document.addEventListener("drop", (event) => {
    const target = dropTargetFor(event.target);
    if (!target) return;
    event.preventDefault();
    const item = dragItem;
    clearDropHighlight();
    if (item.kind === "host") scheduleMove("host", item.id, target.dataset.group);
    else scheduleMove("snippet", item.id, target.dataset.packageId);
  });

  document.addEventListener("dragend", () => {
    clearDropHighlight();
    document.querySelectorAll(".dragging").forEach((el) => el.classList.remove("dragging"));
    document.body.classList.remove("dragging-host", "dragging-snippet");
    dragItem = null;
  });
}

/* --------------------------------------------------------------------------
   MD3 ripple: a wave of the element's content colour grows from the press
   point. It is drawn in an overlay clipped to the element's box and radius
   (not inside the element), because most clicks call render(), which would
   destroy an in-element ripple a few milliseconds after it started.
   -------------------------------------------------------------------------- */
const RIPPLE_TARGETS = [
  "button",
  ".btn",
  ".side-item",
  ".tab",
  ".host-card",
  ".group-card",
  ".mini-card",
  ".cmd-item",
  ".cmd-category",
  ".md-combo-option",
  ".lang-option",
  ".package-member",
  "tr[data-sftp-path]",
  "[role='tab']",
].join(",");
const RIPPLE_MIN_MS = 225; // keep the wave visible at least this long before fading

function rippleTarget(element) {
  const target = element?.closest?.(RIPPLE_TARGETS);
  if (!target || target.closest("[data-no-ripple], .xterm, #terminalPane")) return null;
  if (target.disabled || target.getAttribute("aria-disabled") === "true" || target.closest(".disabled")) return null;
  return target;
}

function spawnRipple(target, x, y) {
  const rect = target.getBoundingClientRect();
  if (rect.width < 2 || rect.height < 2) return null;
  const style = getComputedStyle(target);
  const host = document.createElement("span");
  host.className = "md-ripple-host";
  host.style.left = `${rect.left}px`;
  host.style.top = `${rect.top}px`;
  host.style.width = `${rect.width}px`;
  host.style.height = `${rect.height}px`;
  host.style.borderRadius = style.borderRadius;
  host.style.color = style.color;

  // Radius that reaches the farthest corner from the press point.
  const px = Math.min(Math.max(x - rect.left, 0), rect.width);
  const py = Math.min(Math.max(y - rect.top, 0), rect.height);
  const radius = Math.hypot(Math.max(px, rect.width - px), Math.max(py, rect.height - py));
  const wave = document.createElement("span");
  wave.className = "md-ripple";
  wave.style.width = wave.style.height = `${radius * 2}px`;
  wave.style.left = `${px - radius}px`;
  wave.style.top = `${py - radius}px`;
  // Larger surfaces get a slightly slower wave, as in MD3.
  wave.style.animationDuration = `${Math.min(550, 300 + radius * 0.6)}ms`;
  host.appendChild(wave);
  document.body.appendChild(host);
  return { host, started: performance.now() };
}

function releaseRipple(ripple) {
  if (!ripple || ripple.released) return;
  ripple.released = true;
  const wait = Math.max(0, RIPPLE_MIN_MS - (performance.now() - ripple.started));
  setTimeout(() => {
    ripple.host.classList.add("fading");
    setTimeout(() => ripple.host.remove(), 260);
  }, wait);
}

function bindRipples() {
  if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
  let active = null;
  document.addEventListener(
    "pointerdown",
    (event) => {
      if (event.button !== 0) return;
      const target = rippleTarget(event.target);
      if (!target) return;
      active = spawnRipple(target, event.clientX, event.clientY);
    },
    true,
  );
  const release = () => {
    releaseRipple(active);
    active = null;
  };
  ["pointerup", "pointercancel", "dragstart", "blur"].forEach((type) =>
    (type === "blur" ? window : document).addEventListener(type, release, true),
  );
  // Keyboard activation ripples from the centre, like MD3.
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.repeat || (event.key !== "Enter" && event.key !== " ")) return;
      const target = rippleTarget(event.target);
      if (!target || target !== event.target) return;
      const rect = target.getBoundingClientRect();
      releaseRipple(spawnRipple(target, rect.left + rect.width / 2, rect.top + rect.height / 2));
    },
    true,
  );
}

function parentPath(path) {
  if (!path || path === "/") return "/";
  const clean = path.replace(/\/+$/, "");
  const idx = clean.lastIndexOf("/");
  return idx <= 0 ? "/" : clean.slice(0, idx);
}

async function pollWatchedFiles() {
  if (!state.watchedFiles.length) return;
  try {
    const before = JSON.stringify(state.watchedFiles.map((file) => [file.remotePath, file.dirty]));
    state.watchedFiles = await call("check_watched_files", { files: state.watchedFiles });
    const after = JSON.stringify(state.watchedFiles.map((file) => [file.remotePath, file.dirty]));
    if (before !== after) render();
  } catch {
    // 临时文件可能被用户删除，做容错处理
  }
}

setInterval(() => {
  if (state.view === "session") {
    refreshMetrics();
    pollWatchedFiles();
  }
}, 5000);

function terminalViewActive() {
  return state.view === "session" || state.view === "localTerminal";
}
function syncFormsToState() {
  if (document.querySelector(".editor") || document.querySelector(".details-panel")) {
    if (state.editingHost && (!state.detailKind || state.detailKind === "host")) readEditor();
    if (state.editingGroup && state.detailKind === "group") readGroupDetails();
    if (state.editingIdentity && state.detailKind === "identity") readIdentityForm();
    if (state.editingKey && state.detailKind === "key") readKeyDetails();
    if (state.editingSnippet && state.detailKind === "snippet") readSnippetDetails();
    if (state.editingPackage && state.detailKind === "package") readPackageDetails();
  }
}

function deleteDialogVisual(item) {
  const type = item.type;
  if (type === "host") {
    const icon = osIcon(item.os);
    return { icon: icon.svg, background: icon.color };
  }
  if (type === "group") return { icon: groupIcon(), background: "var(--blue-2)" };
  if (type === "key") return { icon: keySmallIcon(), background: "var(--blue-2)" };
  if (type === "identity") return { icon: identityIcon(), background: "var(--blue-2)" };
  if (type === "snippet") return { icon: snippetIcon(), background: "var(--blue-2)" };
  if (type === "package") return { icon: packageIcon(), background: "var(--blue-2)" };
  if (type === "folder") {
    return {
      icon: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h7l2 2h9v11H3Z"/></svg>`,
      background: "var(--blue-2)",
    };
  }
  return {
    icon: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 2h9l5 5v15H6Z"/><path d="M15 2v5h5"/></svg>`,
    background: "var(--blue-2)",
  };
}

function renderDeleteDialogItem(item) {
  const allowed = ["host", "group", "key", "identity", "snippet", "folder", "file"];
  const type = allowed.includes(item.type) ? item.type : "file";
  const visual = deleteDialogVisual({ ...item, type });
  return `<div class="delete-dialog-item delete-dialog-item-${type}">
    <span class="delete-dialog-item-icon" style="background:${escapeHtml(visual.background)}">${visual.icon}</span>
    <span class="delete-dialog-item-copy">
      <strong>${escapeHtml(item.title || "")}</strong>
      ${item.subtitle ? `<small>${escapeHtml(item.subtitle)}</small>` : ""}
    </span>
  </div>`;
}

function renderDeleteDialog() {
  const dialog = state.deleteDialog;
  if (!dialog) return "";
  return `
    <div class="delete-dialog-overlay" data-delete-backdrop>
      <section class="delete-dialog" role="dialog" aria-modal="true" aria-labelledby="deleteDialogTitle">
        <header class="delete-dialog-header">
          <h2 id="deleteDialogTitle">${escapeHtml(dialog.title || t("Remove item"))}</h2>
          <button class="icon-btn delete-dialog-close" data-action="cancel-delete-dialog" title="${t("Close")}" aria-label="${t("Close")}">${closeIcon()}</button>
        </header>
        <div class="delete-dialog-body">
          <p>${escapeHtml(dialog.message || t("This action cannot be undone."))}</p>
          ${dialog.item ? renderDeleteDialogItem(dialog.item) : ""}
          ${
            dialog.affected?.length
              ? `<p class="delete-dialog-affected-label">${escapeHtml(dialog.affectedLabel || t("And these items:"))}</p>
                 <div class="delete-dialog-affected">${dialog.affected.map(renderDeleteDialogItem).join("")}</div>`
              : ""
          }
      </div>
      <footer class="delete-dialog-footer">
        <button class="btn delete-dialog-remove" data-action="confirm-delete-dialog"><span>${t("Remove")}</span></button>
      </footer>
      </section>
    </div>
  `;
}

function render(options = {}) {
  if (!state.skipFormSync) syncFormsToState();
  state.skipFormSync = false;
  const active = document.activeElement;
  const activeId = active?.id || "";
  const selectionStart = typeof active?.selectionStart === "number" ? active.selectionStart : null;
  const terminal = document.querySelector("#terminalPane");
  const terminalHadFocus = Boolean(
    active &&
      (terminal?.contains(active) || xterm?.element?.contains(active) || active === xterm?.textarea),
  );
  const shouldRestoreTerminalFocus = Boolean(options.focusTerminal || terminalHadFocus);
  const terminalScroll = terminal?.scrollTop ?? 0;
  const terminalWasAtBottom = terminal
    ? terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight < 16
    : true;
  const table = document.querySelector(".table-wrap");
  const tableScroll = table?.scrollTop ?? 0;
  const bottomScrollEl = document.querySelector(".session-bottom-content");
  const bottomScroll = bottomScrollEl?.scrollTop ?? 0;
  const detailsScrollEl = document.querySelector(".details-scroll");
  const detailsScroll = detailsScrollEl?.scrollTop ?? 0;

  const workspace =
    state.view === "session"
      ? renderSession()
      : state.view === "localTerminal"
        ? renderLocalTerminal()
        : renderDashboard();

  app.innerHTML = `
    <div class="app">
      ${renderTopbar()}
      <div class="workspace" style="position: relative;">
        ${workspace}
        ${state.untrustedHostPrompt ? renderUntrustedHostPrompt() : ""}
      </div>
    </div>
    ${renderDeleteDialog()}
  `;
  app.querySelectorAll("input:not([type=checkbox]):not([type=file])").forEach(el => el.setAttribute("autocomplete", "off"));
  bindEvents();
  syncComboAfterRender();
  if (terminalViewActive()) mountXterm(shouldRestoreTerminalFocus);

  requestAnimationFrame(() => {
    const nextTerminal = document.querySelector("#terminalPane");
    if (nextTerminal && !xterm) {
      if (state.term?.alt) {
        nextTerminal.scrollTop = 0;
      } else if (options.terminalBottom || (!options.keepTerminalScroll && terminalWasAtBottom)) {
        nextTerminal.scrollTop = nextTerminal.scrollHeight;
      } else {
        nextTerminal.scrollTop = terminalScroll;
      }
    }

    const nextTable = document.querySelector(".table-wrap");
    if (nextTable) nextTable.scrollTop = tableScroll;
    
    const nextBottomScroll = document.querySelector(".session-bottom-content");
    if (nextBottomScroll) nextBottomScroll.scrollTop = bottomScroll;
    
    const nextDetailsScroll = document.querySelector(".details-scroll");
    if (nextDetailsScroll) nextDetailsScroll.scrollTop = detailsScroll;

    const focusId = options.focusTerminal ? "terminalPane" : options.focusCommand ? "commandInput" : activeId;
    const focusTarget = focusId ? document.getElementById(focusId) : null;
    if (shouldRestoreTerminalFocus && xterm) {
      xterm.focus();
      return;
    }
    if (focusTarget) {
      focusTarget.focus();
      if (selectionStart !== null && typeof focusTarget.setSelectionRange === "function") {
        const pos = Math.min(selectionStart, focusTarget.value?.length || 0);
        focusTarget.setSelectionRange(pos, pos);
      }
    }
  });
}

function renderTopbar() {
  const terminalLabel = state.sessionKind === "local" ? t("Local Terminal") : t("SSH Workspace");
  const terminalAction = state.sessionKind === "local" ? "local-terminal-tab" : "session-tab";
  return `
    <header class="topbar">
      <div class="lang-menu">
        <button class="icon-btn quiet" onclick="event.stopPropagation(); state.languageMenuOpen = !state.languageMenuOpen; render();" title="${t('Language')}">
          <svg viewBox="0 0 24 24" aria-hidden="true" style="width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
        </button>
        ${state.languageMenuOpen ? `
          <div onclick="event.stopPropagation(); state.languageMenuOpen = false; render();" style="position:fixed; inset:0; z-index:999;"></div>
          <div class="lang-dropdown">
            <div class="lang-option-title">${t('Language')}</div>
            ${LANGUAGES.map((lang) => `<button class="lang-option ${state.language === lang.code ? "active" : ""}" onclick="toggleLanguage('${lang.code}')">${lang.name}</button>`).join("")}
          </div>
        ` : ''}
      </div>
      <div class="brand"><img src="logo.png" alt="logo" style="width: 24px; height: 24px; border-radius: 4px; margin-right: 8px;"><span>VPS Studio</span></div>
      <nav class="top-tabs">
        <button class="tab ${state.view === "dashboard" ? "active" : ""}" data-action="dashboard">${t("Vaults")}</button>
        <button class="tab ${terminalViewActive() ? "active" : ""}" data-action="${terminalAction}">${terminalLabel}</button>
      </nav>
      <div class="top-spacer"></div>
      <div class="status">${escapeHtml(t(state.status))}</div>
      ${
        terminalViewActive()

          ? `<button class="btn ghost" data-action="disconnect">${state.sessionKind === "local" ? t("Close") : t("Disconnect")}</button>`
          : ""
      }
    </header>
  `;
}

function renderUntrustedHostPrompt() {
  const p = state.untrustedHostPrompt;
  return `
    <div class="modal-backdrop" style="position: fixed; inset: 0; z-index: 2000; background: rgba(0, 0, 0, 0.65); backdrop-filter: blur(8px); display: flex; flex-direction: column; justify-content: center; align-items: center;">
      <div class="dialog m3-dialog" style="text-align: center; max-width: 500px; width: 90%; padding: 28px; border-radius: var(--md-sys-shape-corner-extra-large); background: var(--md-sys-color-surface-container-high); box-shadow: var(--md-sys-elevation-3); border: 1px solid var(--md-sys-color-outline-variant);">
        <div style="display:flex; justify-content:center; align-items:center; margin-bottom:20px; gap:16px;">
           <div class="host-mark pink" style="width:48px; height:48px; border-radius: var(--md-sys-shape-corner-medium);">${hostMarkIcon()}</div>
           <div style="text-align:left;">
             <div style="font-weight:700; color:var(--md-sys-color-on-surface); font-size:16px;">${escapeHtml(p.host.name)}</div>
             <div style="color:var(--md-sys-color-on-surface-variant); font-size:12px;">SSH ${escapeHtml(p.host.host)}:${p.host.port}</div>
           </div>
        </div>
        <h3 style="margin-bottom:14px; font-size:18px; font-weight:700; color: var(--md-sys-color-on-surface);">${t("Are you sure you want to connect?")}</h3>
        <p style="margin-bottom:12px; font-size:13.5px; color: var(--md-sys-color-on-surface-variant);">${t("The authenticity of")} <strong style="color: var(--md-sys-color-on-surface);">${escapeHtml(p.host.host)}</strong> ${t("can not be established.")}</p>
        <p style="margin-bottom:16px; font-size:13px; color: var(--md-sys-color-on-surface-variant);">${t("ECDSA fingerprint is SHA256:")}<br/><strong style="word-break:break-all; user-select:all; color: var(--md-sys-color-primary); font-family: 'Cascadia Code', 'SF Mono', monospace; font-size: 12px; display: inline-block; margin-top: 4px;">${escapeHtml(p.fingerprint)}</strong></p>
        <p style="margin-bottom:28px; font-size:13.5px; color: var(--md-sys-color-on-surface);">${t("Do you want to add it to the list of known hosts?")}</p>
        <div class="form-actions" style="display: flex; justify-content: center; gap:12px;">
          <button class="btn ghost" data-action="untrusted-close">${t("Close")}</button>
          <button class="btn ghost" data-action="untrusted-continue">${t("Continue")}</button>
          <button class="btn primary" data-action="untrusted-add">${t("Add and continue")}</button>
        </div>
      </div>
    </div>
  `;
}

function renderDashboard() {
  return `
    <section class="dashboard ${state.detailOpen ? "with-detail" : ""}">
      <aside class="side">${renderSideNav()}</aside>
      <main class="main">${renderDashboardContent()}</main>
      ${state.detailOpen ? renderDetailsPanel() : ""}
      ${state.contextMenu ? renderContextMenu() : ""}
    </section>
  `;
}

function renderSideNav() {
  const items = [
    ["hosts", t("Hosts")],
    ["keychain", t("Keychain")],
    ["snippets", t("Snippets")],
    ["knownHosts", t("Known Hosts")],
    ["logs", t("Logs")],
  ];
  return items
    .map(
      ([id, label]) => `
        <button class="side-item ${state.section === id ? "active" : ""}" data-action="nav" data-section="${id}">
          <span class="side-icon">${sideIcon(id)}</span>
          <span>${escapeHtml(label)}</span>
        </button>
      `,
    )
    .join("");
}

function sideIcon(id) {
  const icons = {
    hosts: `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><circle cx="7" cy="7" r="1"/><circle cx="7" cy="17" r="1"/><line x1="14" y1="7" x2="17" y2="7"/><line x1="14" y1="17" x2="17" y2="17"/></svg>`,
    keychain: `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8.3-8.3M15.5 7.5l3 3M19 4l2 2"/></svg>`,
    snippets: `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
    knownHosts: fingerprintIcon(),
    logs: `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>`,
  };
  return icons[id] || "";
}

function renderDashboardContent() {
  if (state.section === "keychain") return renderKeychainPage();
  if (state.section === "snippets") return renderSnippetsPage();
  if (state.section === "knownHosts") return renderKnownHostsPage();
  if (state.section === "logs") return renderLogsPage();
  return renderHostsPage();
}

function renderHostsPage() {
  const hostList = filteredHosts();
  const groupList = groups();
  return `
    <div class="search-row">
      <div class="search"><input id="hostSearch" value="${escapeAttr(state.search)}" placeholder="${t('Find a host or ssh user@hostname...')}" /></div>
      <button class="btn ghost" disabled>${t("Connect")}</button>
    </div>
    <div class="toolstrip">
      <div class="split">
        <button class="btn primary" data-action="new-host">${btnIcon(plusIcon())}<span>${t("New host")}</span></button>
        <button class="btn square" data-action="toggle-host-menu" title="${t("More options")}">${chevronDownIcon(state.hostMenuOpen)}</button>
        ${state.hostMenuOpen ? renderHostMenu() : ""}
      </div>
      <button class="btn ghost strong" data-action="local-terminal">${btnIcon(terminalIcon())}<span>${t("Terminal")}</span></button>
      ${renderToolstripRight(false)}
    </div>
    ${state.openedGroup ? renderGroupBreadcrumb() : ""}
    ${
      state.openedGroup
        ? ""
        : `
          <div class="section-head"><h2>${t("Groups")}</h2></div>
          <div class="group-grid">
            ${groupList.length ? groupList.map(renderGroupCard).join("") : `<div class="empty">${t("Empty")}</div>`}
          </div>
        `
    }
    <div class="section-head"><h2>${t("Hosts")}</h2></div>
    <div class="host-grid">
      ${
        hostList.length
          ? hostList.map(renderHostCard).join("")
          : `<div class="empty">${t("Empty")}</div>`
      }
    </div>
  `;
}

function renderGroupBreadcrumb() {
  const parts = normalizeGroupPath(state.openedGroup).split("/");
  const crumbs = [
    `<button data-action="show-all-hosts">${t("Hosts")}</button>`,
    ...parts.map((part, index) => {
      const path = parts.slice(0, index + 1).join("/");
      const isLast = index === parts.length - 1;
      return isLast
        ? `<span>${escapeHtml(part)}</span>`
        : `<button data-action="open-breadcrumb-group" data-group="${escapeAttr(path)}">${escapeHtml(part)}</button>`;
    }),
  ];
  return `<nav class="breadcrumb">${crumbs.join(`<span class="crumb-sep">›</span>`)}</nav>`;
}

function hostCountLabel(count) {
  return count === 1 ? t("{0} Host", count) : t("{0} Hosts", count);
}

function renderGroupCard([group, count]) {
  return `
    <article class="group-card ${state.selectedGroup === group ? "active" : ""} ${state.openedGroup === group ? "opened" : ""}" data-group="${escapeAttr(group)}">
      <div class="host-mark blue">${groupIcon()}</div>
      <div>
        <div class="group-title">${escapeHtml(groupLabel(group))}</div>
        <div class="group-meta">${escapeHtml(hostCountLabel(count))}</div>
      </div>
      <button class="card-edit" title="${t("Edit group")}" data-action="edit-group" data-group="${escapeAttr(group)}">${pencilIcon()}</button>
    </article>
  `;
}

function renderHostMenu() {
  return `
    <div class="dropdown-menu wide">
      <button data-action="new-group">${btnIcon(groupIcon())}<span>${t("New Group")}</span></button>
    </div>
  `;
}

function renderHostCard(host) {
  const auth = authLabel(host.auth);
  const { svg, color } = osIcon(host.os);
  return `
    <article class="host-card ${state.selectedHostId === host.id ? "active" : ""}" data-host-id="${escapeAttr(host.id)}" draggable="true">
      <div class="host-mark" style="background: ${color};">${svg}</div>
      <div>
        <div class="host-name">${escapeHtml(host.name)}</div>
        <div class="host-meta">ssh, ${escapeHtml(host.username)}</div>
      </div>
      <div class="host-actions">
        <button class="card-edit" title="${t("Edit host")}" data-action="edit-host" data-host-id="${escapeAttr(host.id)}">${pencilIcon()}</button>
      </div>
    </article>
  `;
}

function renderContextMenu() {
  const menu = state.contextMenu;
  const left = Math.max(8, Math.min(menu.x, window.innerWidth - 260));
  const top = Math.max(8, Math.min(menu.y, window.innerHeight - 230));
  if (menu.kind === "snippet") {
    return `
      <div class="context-menu compact" style="left:${left}px;top:${top}px">
        <button data-action="ctx-edit-snippet">${pencilIcon()} <span>${t("Edit")}</span></button>
        <button class="danger-text" data-action="ctx-remove-snippet">${trashIcon()} <span>${t("Remove")}</span></button>
      </div>
    `;
  }
  if (menu.kind === "package") {
    return `
      <div class="context-menu compact" style="left:${left}px;top:${top}px">
        <button data-action="ctx-edit-package">${pencilIcon()} <span>${t("Edit")}</span></button>
        <button class="danger-text" data-action="ctx-remove-package">${trashIcon()} <span>${t("Remove")}</span></button>
      </div>
    `;
  }
  if (menu.kind === "known_host") {
    return `
      <div class="context-menu compact" style="left:${left}px;top:${top}px">
        <button data-action="ctx-convert-known-host">${serverIcon()} <span>${t("Convert to Host")}</span></button>
        <button class="danger-text" data-action="ctx-remove-known-host">${trashIcon()} <span>${t("Remove")}</span></button>
      </div>
    `;
  }
  if (menu.kind === "key") {
    return `
      <div class="context-menu compact" style="left:${left}px;top:${top}px">
        <button data-action="ctx-edit-key">${pencilIcon()} <span>${t("Edit")}</span></button>
        <button class="danger-text" data-action="ctx-remove-key">${trashIcon()} <span>${t("Remove")}</span></button>
      </div>
    `;
  }
  if (menu.kind === "identity") {
    return `
      <div class="context-menu compact" style="left:${left}px;top:${top}px">
        <button data-action="ctx-edit-identity">${pencilIcon()} <span>${t("Edit")}</span></button>
        <button class="danger-text" data-action="ctx-remove-identity">${trashIcon()} <span>${t("Remove")}</span></button>
      </div>
    `;
  }
  if (menu.kind === "group") {
    return `
      <div class="context-menu" style="left:${left}px;top:${top}px">
        <button data-action="ctx-connect-group">${plugIcon()} <span>${t("Connect")}</span></button>
        <button data-action="ctx-edit-group">${pencilIcon()} <span>${t("Edit Group Details")}</span></button>
        <button class="danger-text" data-action="ctx-remove-group">${trashIcon()} <span>${t("Remove")}</span></button>
      </div>
    `;
  }
  return `
    <div class="context-menu" style="left:${left}px;top:${top}px">
      <button data-action="ctx-connect-host">${plugIcon()} <span>${t("Connect")}</span></button>
      <button data-action="ctx-edit-host">${pencilIcon()} <span>${t("Edit Host Details")}</span></button>
      <button data-action="ctx-duplicate-host">${copyIcon()} <span>${t("Duplicate")}</span></button>
      <button class="danger-text" data-action="ctx-remove-host">${trashIcon()} <span>${t("Remove")}</span></button>
    </div>
  `;
}

function contextHost() {
  const id = state.contextMenu?.id;
  return state.hosts.find((host) => host.id === id);
}

function contextGroup() {
  return state.contextMenu?.group || "";
}

function contextKnownHost() {
  const id = state.contextMenu?.id;
  return state.knownHosts?.find((h) => h.id === id);
}

function contextKey() {
  const id = state.contextMenu?.id;
  return state.keys.find((key) => key.id === id);
}

function contextSnippet() {
  const id = state.contextMenu?.id;
  return state.snippets.find((s) => s.id === id);
}

function pencilIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`;
}

// Leading icon for toolbar buttons and menu items.
function btnIcon(svg) {
  return `<span class="btn-icon" aria-hidden="true">${svg}</span>`;
}

function plusIcon() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>`;
}

function terminalIcon() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4" width="19" height="16" rx="2.5"/><path d="m7 9.5 3 2.5-3 2.5M12.5 15H17"/></svg>`;
}

function historyIcon() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>`;
}

function importIcon() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/></svg>`;
}

function generateKeyIcon() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 7.8-7.8M16 7l2.5 2.5M18.5 4.5 21 7"/><path d="M19 13.5v3M17.5 15h3"/></svg>`;
}

function chevronDownIcon(isOpen = false) {
  return `<svg class="chevron-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; transition: transform 0.2s ease; transform: ${isOpen ? 'rotate(180deg)' : 'none'};"><polyline points="6 9 12 15 18 9"/></svg>`;
}

function sortIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:18px;height:18px;"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="14" y2="12"/><line x1="4" y1="18" x2="8" y2="18"/></svg>`;
}

function sortAzIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><line x1="5" y1="4" x2="5" y2="20"/><polyline points="2.5 16.5 5 19.5 7.5 16.5"/><path d="M12.5 10.5 15.5 4.5l3 6M13.3 8.8h4.4"/><path d="M13 15h5.5l-5.5 5h5.5"/></svg>`;
}

function sortZaIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><line x1="5" y1="4" x2="5" y2="20"/><polyline points="2.5 16.5 5 19.5 7.5 16.5"/><path d="M13 4.5h5.5l-5.5 5h5.5"/><path d="M12.5 20.5 15.5 14.5l3 6M13.3 18.8h4.4"/></svg>`;
}

function calendarIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`;
}

function calendarDescIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><rect x="3" y="4" width="18" height="17" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="12" y1="12" x2="12" y2="17"/><polyline points="9.5 14.5 12 17 14.5 14.5"/></svg>`;
}

function calendarAscIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><rect x="3" y="4" width="18" height="17" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="12" y1="17" x2="12" y2="12"/><polyline points="9.5 14.5 12 12 14.5 14.5"/></svg>`;
}

function checkIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><polyline points="20 6 9 17 4 12"/></svg>`;
}

function searchIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:18px;height:18px;"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/></svg>`;
}


// Material Design "dns" (server) icon
function serverIcon() {
  return `<svg class="md-filled-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M19 13H5c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h14c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zm-1 6H6v-4h12v4zM7 18h2v-2H7v2zM19 3H5c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h14c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zm-1 6H6V5h12v4zM7 8h2V6H7v2z"/></svg>`;
}

function plugIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3v5M16 3v5M7 8h10v3a5 5 0 0 1-10 0V8Z"/><path d="M12 16v5"/></svg>`;
}

function copyIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
}

function trashIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>`;
}

function closeIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
}

function fingerprintIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
    <path d="M6.89 4.31C7.65 3.89 8.48 3.57 9.37 3.35C10.20 3.14 11.09 3.03 12.00 3.03C12.89 3.03 13.76 3.14 14.58 3.33C15.48 3.55 16.33 3.88 17.11 4.31"/>
    <path d="M5.19 9.84C5.83 8.77 6.86 7.88 8.13 7.28C8.66 7.03 9.24 6.82 9.85 6.68C10.53 6.52 11.25 6.43 12.00 6.43C12.74 6.43 13.46 6.52 14.13 6.68C14.89 6.85 15.60 7.12 16.23 7.47C17.34 8.06 18.23 8.88 18.81 9.84"/>
    <path d="M6.43 17.50C6.04 16.41 6.04 15.30 6.04 15.30C6.04 12.29 8.60 9.84 12.00 9.84C15.40 9.84 17.96 12.29 17.96 15.30C17.96 15.30 17.96 15.46 17.96 15.46C17.96 16.59 17.05 17.50 15.92 17.50C15.09 17.50 14.35 16.99 14.04 16.22C14.04 16.22 13.36 14.52 13.36 14.52C13.06 13.74 12.31 13.24 11.48 13.24C10.36 13.24 9.45 14.15 9.45 15.27C9.45 16.12 9.68 16.94 10.10 17.64C10.38 18.12 10.74 18.54 11.18 18.89C11.18 18.89 11.57 19.20 11.57 19.20"/>
    <path d="M16.25 20.05C15.71 20.55 15.09 20.96 14.41 21.25C13.99 21.44 13.54 21.57 13.08 21.65C12.73 21.72 12.37 21.75 12.00 21.75C11.53 21.75 11.08 21.70 10.64 21.60C10.22 21.50 9.83 21.37 9.45 21.19C8.82 20.91 8.25 20.52 7.75 20.05"/>
  </svg>`;
}

function osIcon(os) {
  const defaultIcon = { svg: `<svg viewBox="0 0 24 24" aria-hidden="true" style="fill:none; stroke:currentColor; stroke-width:2; stroke-linecap:round; stroke-linejoin:round;"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><circle cx="7" cy="7" r="1"/><circle cx="7" cy="17" r="1"/><line x1="14" y1="7" x2="17" y2="7"/><line x1="14" y1="17" x2="17" y2="17"/></svg>`, color: "var(--md-sys-color-primary)" };
  if (!os) return defaultIcon;
  const lower = os.toLowerCase();
  
  if (lower.includes("debian")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M13.88 12.685c-.4 0 .08.2.601.28.14-.1.27-.22.39-.33a3.001 3.001 0 01-.99.05m2.14-.53c.23-.33.4-.69.47-1.06-.06.27-.2.5-.33.73-.75.47-.07-.27 0-.56-.8 1.01-.11.6-.14.89m.781-2.05c.05-.721-.14-.501-.2-.221.07.04.13.5.2.22M12.38.31c.2.04.45.07.42.12.23-.05.28-.1-.43-.12m.43.12l-.15.03.14-.01V.43m6.633 9.944c.02.64-.2.95-.38 1.5l-.35.181c-.28.54.03.35-.17.78-.44.39-1.34 1.22-1.62 1.301-.201 0 .14-.25.19-.34-.591.4-.481.6-1.371.85l-.03-.06c-2.221 1.04-5.303-1.02-5.253-3.842-.03.17-.07.13-.12.2a3.551 3.552 0 012.001-3.501 3.361 3.362 0 013.732.48 3.341 3.342 0 00-2.721-1.3c-1.18.01-2.281.76-2.651 1.57-.6.38-.67 1.47-.93 1.661-.361 2.601.66 3.722 2.38 5.042.27.19.08.21.12.35a4.702 4.702 0 01-1.53-1.16c.23.33.47.66.8.91-.55-.18-1.27-1.3-1.48-1.35.93 1.66 3.78 2.921 5.261 2.3a6.203 6.203 0 01-2.33-.28c-.33-.16-.77-.51-.7-.57a5.802 5.803 0 005.902-.84c.44-.35.93-.94 1.07-.95-.2.32.04.16-.12.44.44-.72-.2-.3.46-1.24l.24.33c-.09-.6.74-1.321.66-2.262.19-.3.2.3 0 .97.29-.74.08-.85.15-1.46.08.2.18.42.23.63-.18-.7.2-1.2.28-1.6-.09-.05-.28.3-.32-.53 0-.37.1-.2.14-.28-.08-.05-.26-.32-.38-.861.08-.13.22.33.34.34-.08-.42-.2-.75-.2-1.08-.34-.68-.12.1-.4-.3-.34-1.091.3-.25.34-.74.54.77.84 1.96.981 2.46-.1-.6-.28-1.2-.49-1.76.16.07-.26-1.241.21-.37A7.823 7.824 0 0017.702 1.6c.18.17.42.39.33.42-.75-.45-.62-.48-.73-.67-.61-.25-.65.02-1.06 0C15.082.73 14.862.8 13.8.4l.05.23c-.77-.25-.9.1-1.73 0-.05-.04.27-.14.53-.18-.741.1-.701-.14-1.431.03.17-.13.36-.21.55-.32-.6.04-1.44.35-1.18.07C9.6.68 7.847 1.3 6.867 2.22L6.838 2c-.45.54-1.96 1.611-2.08 2.311l-.131.03c-.23.4-.38.85-.57 1.261-.3.52-.45.2-.4.28-.6 1.22-.9 2.251-1.16 3.102.18.27 0 1.65.07 2.76-.3 5.463 3.84 10.776 8.363 12.006.67.23 1.65.23 2.49.25-.99-.28-1.12-.15-2.08-.49-.7-.32-.85-.7-1.34-1.13l.2.35c-.971-.34-.57-.42-1.361-.67l.21-.27c-.31-.03-.83-.53-.97-.81l-.34.01c-.41-.501-.63-.871-.61-1.161l-.111.2c-.13-.21-1.52-1.901-.8-1.511-.13-.12-.31-.2-.5-.55l.14-.17c-.35-.44-.64-1.02-.62-1.2.2.24.32.3.45.33-.88-2.172-.93-.12-1.601-2.202l.15-.02c-.1-.16-.18-.34-.26-.51l.06-.6c-.63-.74-.18-3.102-.09-4.402.07-.54.53-1.1.88-1.981l-.21-.04c.4-.71 2.341-2.872 3.241-2.761.43-.55-.09 0-.18-.14.96-.991 1.26-.7 1.901-.88.7-.401-.6.16-.27-.151 1.2-.3.85-.7 2.421-.85.16.1-.39.14-.52.26 1-.49 3.151-.37 4.562.27 1.63.77 3.461 3.011 3.531 5.132l.08.02c-.04.85.13 1.821-.17 2.711l.2-.42M9.54 13.236l-.05.28c.26.35.47.73.8 1.01-.24-.47-.42-.66-.75-1.3m.62-.02c-.14-.15-.22-.34-.31-.52.08.32.26.6.43.88l-.12-.36m10.945-2.382l-.07.15c-.1.76-.34 1.511-.69 2.212.4-.73.65-1.541.75-2.362M12.45.12c.27-.1.66-.05.95-.12-.37.03-.74.05-1.1.1l.15.02M3.006 5.142c.07.57-.43.8.11.42.3-.66-.11-.18-.1-.42m-.64 2.661c.12-.39.15-.62.2-.84-.35.44-.17.53-.2.83"/></svg>`, color: "#d70a53" };
  }
  if (lower.includes("ubuntu")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M17.61.455a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zM12.92.8C8.923.777 5.137 2.941 3.148 6.451a4.5 4.5 0 0 1 .26-.007 4.92 4.92 0 0 1 2.585.737A8.316 8.316 0 0 1 12.688 3.6 4.944 4.944 0 0 1 13.723.834 11.008 11.008 0 0 0 12.92.8zm9.226 4.994a4.915 4.915 0 0 1-1.918 2.246 8.36 8.36 0 0 1-.273 8.303 4.89 4.89 0 0 1 1.632 2.54 11.156 11.156 0 0 0 .559-13.089zM3.41 7.932A3.41 3.41 0 0 0 0 11.342a3.41 3.41 0 0 0 3.41 3.409 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zm2.027 7.866a4.908 4.908 0 0 1-2.915.358 11.1 11.1 0 0 0 7.991 6.698 11.234 11.234 0 0 0 2.422.249 4.879 4.879 0 0 1-.999-2.85 8.484 8.484 0 0 1-.836-.136 8.304 8.304 0 0 1-5.663-4.32zm11.405.928a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41z"/></svg>`, color: "#E95420" };
  }
  if (lower.includes("alpine")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M5.998 1.607L0 12l5.998 10.393h12.004L24 12 18.002 1.607H5.998zM9.965 7.12L12.66 9.9l1.598 1.595.002-.002 2.41 2.363c-.2.14-.386.252-.563.344a3.756 3.756 0 01-.496.217 2.702 2.702 0 01-.425.111c-.131.023-.25.034-.358.034-.13 0-.242-.014-.338-.034a1.317 1.317 0 01-.24-.072.95.95 0 01-.2-.113l-1.062-1.092-3.039-3.041-1.1 1.053-3.07 3.072a.974.974 0 01-.2.111 1.274 1.274 0 01-.237.073c-.096.02-.209.033-.338.033-.108 0-.227-.009-.358-.031a2.7 2.7 0 01-.425-.114 3.748 3.748 0 01-.496-.217 5.228 5.228 0 01-.563-.343l6.803-6.727zm4.72.785l4.579 4.598 1.382 1.353a5.24 5.24 0 01-.564.344 3.73 3.73 0 01-.494.217 2.697 2.697 0 01-.426.111c-.13.023-.251.034-.36.034-.129 0-.241-.014-.337-.034a1.285 1.285 0 01-.385-.146c-.033-.02-.05-.036-.053-.04l-1.232-1.218-2.111-2.111-.334.334L12.79 9.8l1.896-1.897zm-5.966 4.12v2.529a2.128 2.128 0 01-.356-.035 2.765 2.765 0 01-.422-.116 3.708 3.708 0 01-.488-.214 5.217 5.217 0 01-.555-.34l1.82-1.825Z"/></svg>`, color: "#0D597F" };
  }
  if (lower.includes("centos")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M12.076.066L8.883 3.28H3.348v5.434L0 12.01l3.349 3.298v5.39h5.374l3.285 3.236 3.285-3.236h5.43v-5.374L24 12.026l-3.232-3.252V3.321H15.31zm0 .749l2.49 2.506h-1.69v6.441l-.8.805-.81-.815V3.28H9.627zm-8.2 2.991h4.483L6.485 5.692l4.253 4.279v.654H9.94L5.674 6.423l-1.798 1.77zm5.227 0h1.635v5.415l-3.509-3.53zm4.302.043h1.687l1.83 1.842-3.517 3.539zm2.431 0h4.404v4.394l-1.83-1.842-4.241 4.267h-.764v-.69l4.261-4.287zm2.574 3.3l1.83 1.843v1.676h-5.327zm-12.735.013l3.515 3.462H3.876v-1.69zM3.348 9.454v1.697h6.377l.871.858-.782.77H3.35v1.786L.753 12.01zm17.42.068l2.488 2.503-2.533 2.55v-1.796h-6.41l-.75-.754.825-.83h6.38zm-9.502.978l.81.815.186-.188.614-.618v.686h.768l-.825.83.75.754h-.719v.808l-.842-.83-.741.73v-.707h-.7l.781-.77-.188-.186-.682-.672h.788zm-7.39 2.807h5.402l-3.603 3.55-1.798-1.772zm6.154 0h.708v.7l-4.404 4.338 1.852 1.824h-4.31v-4.342l1.798 1.77zm3.348 0h.715l4.317 4.343.186-.187 1.599-1.61v4.316h-4.366l1.853-1.825-.188-.185-4.116-4.054zm1.46 0h5.357v1.798l-1.785 1.796zm-2.83.191l.842.829v6.37h1.691l-2.532 2.495-2.533-2.495h1.79V14.23zm-1.27 1.251v5.42H8.939l-1.852-1.823zm2.64.097l3.552 3.499-1.853 1.825h-1.7z"/></svg>`, color: "#262577" };
  }
  if (lower.includes("almalinux")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M23.994 15.133c.079 1.061-.668 1.927-1.69 2.005a1.8 1.8 0 0 1-1.928-1.651c-.078-1.062.63-1.849 1.691-1.967 1.023-.078 1.849.59 1.927 1.613zm-12.623 4.955c-.944 0-1.73.786-1.73 1.809 0 1.14.747 1.848 1.887 1.848.904-.04 1.691-.865 1.691-1.809 0-.983-.904-1.848-1.848-1.848zm1.061-9.675c-.039-.865-.078-1.73.08-2.556.156-.944.314-1.887.904-2.674.707-.983 1.809-.944 2.399.118.314.511.432 1.062.471 1.652 0 .354.158.432.472.393.944-.157 1.888-.157 2.792.197.118.039.236.118.394 0 .314-.276.393-1.652.196-2.006-.354-.63-.904-.55-1.455-.55-.629.039-1.18-.158-1.612-.67-.393-.471-.511-1.06-.59-1.65-.04-.276-.079-.512-.315-.709-.55-.55-1.809-.432-2.477.118-2.556 2.045-2.989 5.467-1.534 8.18.04.118.118.236.275.157zm7.984 3.658c.354-.511.865-.747 1.415-.983a.973.973 0 0 0 .59-.472c.354-.669-.078-1.81-.747-2.36-2.595-2.006-5.938-1.612-8.18.433-.118.078-.157.196-.078.314.786-.236 1.612-.472 2.477-.51.905-.08 1.848-.158 2.753.235 1.14.472 1.337 1.534.472 2.36-.393.393-.905.668-1.455.825-.315.08-.354.236-.236.551.354.865.59 1.77.472 2.753-.04.157-.079.275.078.393.354.236 1.691 0 1.967-.275.511-.472.314-1.023.196-1.534-.157-.63-.078-1.219.276-1.73zm-7.197-2.045c-.118-.079-.197-.118-.315 0 .472.708.905 1.455 1.259 2.241.314.866.668 1.73.55 2.714-.118 1.18-1.1 1.69-2.123 1.101-.511-.275-.905-.669-1.22-1.14-.196-.276-.393-.276-.629-.08-.747.63-1.533 1.102-2.516 1.26-.158 0-.315 0-.394.157-.118.393.472 1.612.826 1.809.59.354 1.062 0 1.534-.276.55-.314 1.101-.432 1.73-.236.59.197.983.63 1.337 1.102.158.196.315.353.63.432.747.197 1.77-.59 2.084-1.376 1.18-3.028-.157-6.135-2.753-7.708zm-2.556 2.438c.472-.669.826-1.416.983-2.202-.157-.04-.197.04-.315.078-.904.944-1.848 1.849-3.067 2.478-.472.236-.983.433-1.534.433-.865 0-1.376-.551-1.298-1.416a2.92 2.92 0 0 1 .787-1.849c.236-.275.236-.432-.04-.668-.786-.55-1.494-1.22-1.848-2.124-.078-.275-.275-.275-.51-.157a4.293 4.293 0 0 0-.434.236c-1.022.63-1.14 1.416-.275 2.28.63.63.944 1.338.708 2.203-.118.433-.354.747-.63 1.101a.95.95 0 0 0-.235.787c.079.747.826 1.494 1.73 1.573 2.517.236 4.562-.63 5.978-2.753zm-4.68-5.152c1.376 1.18 3.067 1.455 4.837 1.377.157 0 .315 0 .354-.118.04-.197-.157-.197-.275-.236-.826-.354-1.691-.63-2.438-1.14S6.848 8.25 6.534 7.266c-.236-.747.078-1.415.825-1.651.669-.236 1.337-.236 1.967 0 .393.157.55.078.629-.354.118-.747.354-1.455.826-2.085.55-.786.55-.865-.354-1.376-.04 0-.04-.04-.079-.04-.865-.471-1.534-.196-1.848.709-.472 1.376-1.377 1.887-2.832 1.612-.196-.04-.393-.079-.472-.079-.747.118-1.18.55-1.297 1.14-.158 1.81.786 3.107 2.084 4.17zm-2.32 3.658c-.079-.944-1.023-1.652-2.045-1.534-.905.079-1.691 1.022-1.613 1.966.08.983 1.023 1.77 1.967 1.652 1.14-.079 1.73-1.18 1.69-2.084zm15.18-8.298c.943-.079 1.73-.983 1.651-1.927-.078-.983-1.022-1.77-2.005-1.691-1.023.079-1.73.983-1.652 1.966s.983 1.73 2.006 1.652zm-12.27-.826c1.062-.157 1.77-1.023 1.652-2.045C8.107.897 7.163.149 6.18.267c-1.062.118-1.691.944-1.573 2.085.118.865 1.061 1.612 1.966 1.494z"/></svg>`, color: "#00A4A6" };
  }
  if (lower.includes("rocky")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M23.332 15.957c.433-1.239.668-2.57.668-3.957 0-6.627-5.373-12-12-12S0 5.373 0 12c0 3.28 1.315 6.251 3.447 8.417L15.62 8.245l3.005 3.005zm-2.192 3.819l-5.52-5.52L6.975 22.9c1.528.706 3.23 1.1 5.025 1.1 3.661 0 6.94-1.64 9.14-4.224z"/></svg>`, color: "#10B981" };
  }
  if (lower.includes("fedora")) {
    return { svg: `<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="fill:currentColor; stroke:none;"><path d="M12.001 0C5.376 0 .008 5.369.004 11.992H.002v9.287h.002A2.726 2.726 0 0 0 2.73 24h9.275c6.626-.004 11.993-5.372 11.993-11.997C23.998 5.375 18.628 0 12 0zm2.431 4.94c2.015 0 3.917 1.543 3.917 3.671 0 .197.001.395-.03.619a1.002 1.002 0 0 1-1.137.893 1.002 1.002 0 0 1-.842-1.175 2.61 2.61 0 0 0 .013-.337c0-1.207-.987-1.672-1.92-1.672-.934 0-1.775.784-1.777 1.672.016 1.027 0 2.046 0 3.07l1.732-.012c1.352-.028 1.368 2.009.016 1.998l-1.748.013c-.004.826.006.677.002 1.093 0 0 .015 1.01-.016 1.776-.209 2.25-2.124 4.046-4.424 4.046-2.438 0-4.448-1.993-4.448-4.437.073-2.515 2.078-4.492 4.603-4.469l1.409-.01v1.996l-1.409.013h-.007c-1.388.04-2.577.984-2.6 2.47a2.438 2.438 0 0 0 2.452 2.439c1.356 0 2.441-.987 2.441-2.437l-.001-7.557c0-.14.005-.252.02-.407.23-1.848 1.883-3.256 3.754-3.256z"/></svg>`, color: "#294172" };
  }
  
  return defaultIcon;
}

function groupIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`;
}

function gridIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/></svg>`;
}

function hostMarkIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21c-4.2-2.8-7-6.2-7-10a7 7 0 0 1 14 0c0 3.8-2.8 7.2-7 10Z"/><circle cx="12" cy="11" r="2.5"/></svg>`;
}

function keySmallIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8.3-8.3M15.5 7.5l3 3M19 4l2 2"/></svg>`;
}

function passwordIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/></svg>`;
}

function renderToolstripRight(showSearchBox = false) {
  return `
    <div style="flex: 1;"></div>
    ${showSearchBox ? `
      ${state.showSearch ? `
        <div class="search local-search-box" style="flex: 0 0 200px; margin-right: 8px;">
          <span style="position: absolute; left: 14px; top: 50%; transform: translateY(-50%); opacity: 0.5; pointer-events: none; display: flex; z-index: 1;">${searchIcon()}</span>
          <input id="localSearch" style="padding-left: 42px; height: 38px;" value="${escapeAttr(state.search)}" placeholder="${t('Search...')}" autocomplete="off" />
        </div>
      ` : `
        <button class="btn square ghost" style="margin-right: 8px;" data-action="toggle-search">${searchIcon()}</button>
      `}
    ` : ""}
    <div style="position: relative;">
      <button class="btn square ghost" data-action="toggle-sort-menu">${sortIcon()}</button>
      ${state.sortMenuOpen ? renderSortMenu() : ""}
    </div>
  `;
}

function renderKeychainPage() {
  const keys = applySort(state.keys.filter(k => !state.search || k.label.toLowerCase().includes(state.search.toLowerCase())), k => k.label);
  const idents = applySort(state.identities.filter(i => {
    const q = state.search.toLowerCase();
    return !q || i.label.toLowerCase().includes(q) || (i.username || "").toLowerCase().includes(q);
  }), i => i.label);

  return `
    <div class="toolstrip first">
      <div class="split">
        <button class="btn primary" data-action="new-key">${btnIcon(plusIcon())}<span>${t("New key")}</span></button>
        <button class="btn square" data-action="toggle-key-menu" title="${t("More options")}">${chevronDownIcon(state.keyMenuOpen)}</button>
        ${state.keyMenuOpen ? renderKeyMenu() : ""}
      </div>
      ${renderToolstripRight(true)}
    </div>
    <div class="section-head"><h2>${t("Keys")}</h2></div>
    <div class="page-grid" style="margin-bottom: 24px;">
      ${
        keys.length
          ? keys.map(renderKeyCard).join("")
          : (state.search ? `<div class="empty">${t("No keys match the search.")}</div>` : `<div class="empty">${t("No keys yet. Add a key or import a private key file.")}</div>`)
      }
    </div>
    <div class="section-head"><h2>${t("Identities")}</h2></div>
    <div class="page-grid">
      ${
        idents.length
          ? idents.map(renderIdentityCard).join("")
          : (state.search ? `<div class="empty">${t("No identities match the search.")}</div>` : `<div class="empty">${t("Empty")}</div>`)
      }
    </div>
  `;
}

function renderKeyMenu() {
  return `
    <div class="dropdown-overlay" data-action="close-all-menus" style="position:fixed; inset:0; z-index:9;"></div>
    <div class="dropdown-menu" style="z-index:10;">
      <button data-action="generate-key">${btnIcon(generateKeyIcon())}<span>${t("Generate key")}</span></button>
      <button data-action="new-identity">${btnIcon(identityIcon())}<span>${t("New Identity")}</span></button>
    </div>
  `;
}

function renderSortMenu() {
  const modes = [
    { id: "a-z", label: "a-z", icon: sortAzIcon() },
    { id: "z-a", label: "z-a", icon: sortZaIcon() },
    { id: "newest", label: "Newest to oldest", icon: calendarDescIcon() },
    { id: "oldest", label: "Oldest to newest", icon: calendarAscIcon() },
  ];
  return `
    <div class="dropdown-menu right" style="min-width: 180px; left: auto; right: 0;">
      ${modes.map(m => `
        <button data-action="set-sort-mode" data-sort-mode="${m.id}" style="display: flex; align-items: center; justify-content: space-between; width: 100%; color: ${state.sortMode === m.id ? 'var(--text)' : 'var(--muted)'};">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="opacity: ${state.sortMode === m.id ? '1' : '0.6'}; width: 16px; height: 16px; display: inline-flex; align-items: center; justify-content: center;">${m.icon}</span>
            <span style="font-size: 13px; font-weight: 600;">${escapeHtml(t(m.label))}</span>
          </div>
          ${state.sortMode === m.id ? `<span style="color: var(--text);">${checkIcon()}</span>` : ""}
        </button>
      `).join("")}
    </div>
  `;
}

function renderKeyCard(key) {
  return `
    <article class="mini-card key-card ${state.selectedKeyId === key.id ? "active" : ""}" data-key-id="${escapeAttr(key.id)}">
      <div class="mini-icon">${keySmallIcon()}</div>
      <div class="card-content">
        <div class="host-name truncate-text">${escapeHtml(keyLabel(key))}</div>
        <div class="host-meta truncate-text">${getKeyTypeDisplay(key)}</div>
      </div>
      <button class="card-edit" title="${t("Edit key")}" data-action="edit-key" data-key-id="${escapeAttr(key.id)}">${pencilIcon()}</button>
    </article>
  `;
}

function getKeyTypeDisplay(key) {
  if (key.type) return `${t("Type")} ${key.type.toUpperCase()}`;
  if (key.publicKey) {
    const pub = key.publicKey.trim().toLowerCase();
    if (pub.startsWith("ssh-rsa")) return `${t("Type")} RSA`;
    if (pub.startsWith("ecdsa-sha2-")) return `${t("Type")} ECDSA`;
    if (pub.startsWith("ssh-ed25519")) return `${t("Type")} ED25519`;
  }
  if (key.privateKey) {
    const pk = key.privateKey.toUpperCase();
    if (pk.includes("RSA PRIVATE KEY")) return `${t("Type")} RSA`;
    if (pk.includes("EC PRIVATE KEY")) return `${t("Type")} ECDSA`;
    if (pk.includes("OPENSSH PRIVATE KEY")) return `${t("Type")} OpenSSH`;
    return t("Private Key");
  }
  return t("Public Key");
}

function identityIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3"/><circle cx="12" cy="12" r="2.5"/><path d="M7.5 18c0-1.8 2-2.5 4.5-2.5s4.5.7 4.5 2.5"/></svg>`;
}

function renderIdentityCard(ident) {
  const authText = ident.auth?.kind === "password" ? t("Auth password") : t("Auth key");
  return `
    <article class="mini-card identity-card ${state.selectedIdentityId === ident.id ? "active" : ""}" data-identity-id="${escapeAttr(ident.id)}">
      <div class="mini-icon" style="background: var(--md-sys-color-primary-container); color: var(--md-sys-color-on-primary-container);">${identityIcon()}</div>
      <div class="card-content">
        <div class="host-name truncate-text">${escapeHtml(identityLabel(ident))}</div>
        <div class="host-meta truncate-text">${authText}</div>
      </div>
      <button class="card-edit" title="${t("Edit identity")}" data-action="edit-identity" data-identity-id="${escapeAttr(ident.id)}">${pencilIcon()}</button>
    </article>
  `;
}

function renderSnippetsPage() {
  const q = state.search.toLowerCase();
  const snippets = applySort(state.snippets.filter((s) => {
    return !q || snippetLabel(s).toLowerCase().includes(q) || s.script.toLowerCase().includes(q);
  }), (s) => snippetLabel(s) || s.script);
  const packages = applySort(state.snippetPackages.filter((pkg) => !q || pkg.name.toLowerCase().includes(q)), (pkg) => pkg.name);
  if (state.openedPackageId && !packageById(state.openedPackageId)) state.openedPackageId = null;
  const opened = packageById(state.openedPackageId);
  // Inside a package: its snippets. At the root: only snippets without a
  // package, except while searching, when every match is shown.
  const visibleSnippets = snippets.filter((s) =>
    opened ? s.packageId === opened.id : q || !packageById(s.packageId),
  );

  return `
    <div class="toolstrip first">
      <div class="split">
        <button class="btn primary" data-action="new-snippet">${btnIcon(plusIcon())}<span>${t("New snippet")}</span></button>
        <button class="btn square" data-action="toggle-snippet-menu" title="${t("More options")}">${chevronDownIcon(state.snippetMenuOpen)}</button>
        ${state.snippetMenuOpen ? renderSnippetMenu() : ""}
      </div>
      <button class="btn ghost strong" data-action="show-shell-history">${btnIcon(historyIcon())}<span>${t("Shell History")}</span></button>
      ${renderToolstripRight(true)}
    </div>
    ${
      opened
        ? `<nav class="breadcrumb"><button data-action="show-all-snippets">${t("All snippets")}</button><span class="crumb-sep">›</span><span>${escapeHtml(packageLabel(opened))}</span></nav>`
        : packages.length
          ? `<div class="section-head"><h2>${t("Packages")}</h2></div>
             <div class="page-grid">${packages.map(renderPackageCard).join("")}</div>`
          : ""
    }
    <div class="section-head"><h2>${t("Snippets")}</h2></div>
    <div class="page-grid">
      ${
        visibleSnippets.length
          ? visibleSnippets.map(renderSnippetCard).join("")
          : (state.search ? `<div class="empty">${t("No snippets match the search.")}</div>` : `<div class="empty">${t("Empty")}</div>`)
      }
    </div>
  `;
}

function snippetIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`;
}

function renderSnippetCard(snippet) {
  const label = snippetLabel(snippet);
  const hasLabel = Boolean(label);
  const title = hasLabel ? label : snippet.script;
  const subtitle = hasLabel ? snippet.script : "";

  return `
    <article class="mini-card snippet-card ${state.selectedSnippetId === snippet.id ? "active" : ""}" data-snippet-id="${escapeAttr(snippet.id)}" draggable="true">
      <div class="mini-icon">${snippetIcon()}</div>
      <div class="card-content">
        <div class="host-name truncate-text ${!hasLabel ? 'code-font' : ''}">${escapeHtml(title)}</div>
        ${subtitle ? `<div class="host-meta truncate-text code-font">${escapeHtml(subtitle)}</div>` : ""}
      </div>
      ${packageById(snippet.packageId) && !state.openedPackageId ? `<span class="package-chip" title="${escapeAttr(t("Package"))}">${packageIcon()}<span class="truncate-text">${escapeHtml(packageById(snippet.packageId).name)}</span></span>` : ""}
      <button class="card-edit" title="${t("Edit snippet")}" data-action="edit-snippet" data-snippet-id="${escapeAttr(snippet.id)}">${pencilIcon()}</button>
    </article>
  `;
}

function renderKnownHostsPage() {
  const items = applySort((state.knownHosts || []).filter(h => {
    const q = state.search.toLowerCase();
    return !q || h.host.toLowerCase().includes(q);
  }), h => h.host);
  return `
    <div class="toolstrip first">
      <button class="btn secondary" data-action="import-known-hosts" ${state.importingKnownHosts ? 'disabled' : ''}>${btnIcon(importIcon())}<span>${state.importingKnownHosts ? t('Importing...') : t('Import')}</span></button>
      ${renderToolstripRight(true)}
    </div>
    <div class="section-head" style="margin-top: 0;">
      <h2>${t("Known Hosts")}</h2>
    </div>
    <div class="page-grid">
      ${
        items.length
          ? items.map((item) => renderKnownHostCard(item)).join("")
          : (state.search ? `<div class="empty">${t("No known hosts match the search.")}</div>` : `<div class="empty">${t("No known hosts. Click Import to load from ~/.ssh/known_hosts")}</div>`)
      }
    </div>
  `;
}

function renderKnownHostCard(item) {
  const label = item.port === 22 ? item.host : `[${item.host}]:${item.port}`;
  return `
    <article class="mini-card known-host-card ${state.selectedKnownHostId === item.id ? "active" : ""}" data-known-host-id="${escapeAttr(item.id)}">
      <div class="mini-icon">${fingerprintIcon()}</div>
      <div class="card-content" style="display:flex; align-items:center;">
        <div class="host-name truncate-text">${escapeHtml(label)}</div>
      </div>
    </article>
  `;
}

function renderLogsPage() {
  const asc = state.logsSortAsc;
  const sortedLogs = asc ? [...state.logs].reverse() : state.logs;
  return `
    <div class="section-head first"><h2>${t("Logs")}</h2></div>
    <div class="log-table">
      <div class="log-head">
        <span style="display:flex; align-items:center; gap:4px; cursor:pointer; user-select:none; width:max-content;" data-action="toggle-logs-sort">
          ${t("Date")} 
          <svg style="width:14px; height:14px; opacity:0.7; transform: ${asc ? 'rotate(180deg)' : 'none'}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 15l5 5 5-5M7 9l5-5 5 5"/></svg>
        </span>
        <span>${t("Host")}</span>
      </div>
      ${
        sortedLogs.length
          ? sortedLogs.map(renderLogRow).join("")
          : `<div class="empty">${t("No logs for this app session yet.")}</div>`
      }
    </div>
  `;
}

function renderLogRow(row) {
  let hostContent = "";
  if (row.host) {
    const matchedHost = (row.hostId && state.hosts.find(h => h.id === row.hostId))
      || state.hosts.find(h => h.name === row.host || h.host === row.host)
      || null;
    const os = row.os || matchedHost?.os || "";
    const { svg, color } = osIcon(os);

    hostContent = `
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="host-mark" style="width:32px; height:32px; border-radius: var(--md-sys-shape-corner-small); background: ${color}; color: #ffffff; display:flex; align-items:center; justify-content:center;">${svg}</div>
        <div style="display:flex; flex-direction:column; gap:2px;">
          <strong style="color:var(--text); font-size:13px; font-weight:600;">${escapeHtml(row.host)}</strong>
          <span style="font-size:12px; color:var(--muted);">ssh, ${escapeHtml(row.user || "root")}</span>
        </div>
      </div>
    `;
  } else {
    hostContent = `
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="host-mark" style="width:32px; height:32px; border-radius: var(--md-sys-shape-corner-small); background: var(--md-sys-color-surface-container-highest); color: var(--md-sys-color-on-surface-variant); display:flex; align-items:center; justify-content:center;">
           <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        </div>
        <div style="display:flex; flex-direction:column; gap:2px;">
          <strong style="color:var(--text); font-size:13px; font-weight:600;">${t("System Event")}</strong>
          <span style="font-size:12px; color:var(--muted);">${escapeHtml(t(row.message))}</span>
        </div>
      </div>
    `;
  }

  const dateObj = row.timestamp ? new Date(row.timestamp) : new Date(row.time);
  const endObj = row.endTimestamp ? new Date(row.endTimestamp) : dateObj;
  
  const locale = currentLocale();
  const dateStr = dateObj.toLocaleDateString(locale, { month: "short", day: "numeric", year: "numeric" });
  const timeStr = dateObj.toLocaleTimeString(locale, { hour12: false, hour: "2-digit", minute: "2-digit" });
  const endTimeStr = endObj.toLocaleTimeString(locale, { hour12: false, hour: "2-digit", minute: "2-digit" });

  return `
    <div class="log-row">
      <div style="display:flex; flex-direction:column; gap:2px;">
        <strong style="color:var(--text); font-size:13px; font-weight:600;">${escapeHtml(dateStr)}</strong>
        <span style="font-size:12px; color:var(--muted);">${escapeHtml(timeStr)} - ${escapeHtml(endTimeStr)}</span>
      </div>
      <div>${hostContent}</div>
    </div>
  `;
}

function renderSession() {
  return `
    <section class="session">
      <aside class="monitor">${renderMonitor()}</aside>
      <main class="session-main">
        <section class="terminal-wrap">
          <div id="terminalPane" class="terminal-xterm" tabindex="0"></div>
          <div class="terminal-input">
            <input id="commandInput" value="${escapeAttr(state.commandInput)}" placeholder="${t("Command input")}" autocomplete="off" />
            <button class="btn primary" data-action="run-command">${t("Run")}</button>
            <button class="btn" data-action="clear-terminal">${t("Clear")}</button>
          </div>
        </section>
        <section class="bottom">
          <div class="bottom-tabs">
            <button class="tab ${state.bottomTab === "files" ? "active" : ""}" data-action="bottom-files">${t("Files")}</button>
            <button class="tab ${state.bottomTab === "commands" ? "active" : ""}" data-action="bottom-commands">${t("Commands")}</button>
            <div class="top-spacer"></div>
            <button class="btn" data-action="refresh-sftp">${t("Refresh")}</button>
          </div>
          ${renderUploadPrompts()}
          ${state.bottomTab === "files" ? renderSftp() : renderSessionSnippets()}
        </section>
      </main>
    </section>
  `;
}

function renderLocalTerminal() {
  return `
    <section class="local-terminal">
      <div id="terminalPane" class="terminal-xterm local-terminal-pane" tabindex="0"></div>
    </section>
  `;
}

function renderTerminalText() {
  const term = ensureTerminal();
  const lines = terminalLines();
  const cursorLine = terminalCursorLineIndex();
  const shouldRenderCaret =
    state.terminalFocused && state.activeShellId && term.cursorVisible;

  return lines
    .map((line, index) => {
      if (!shouldRenderCaret || index !== cursorLine) return escapeHtml(line);
      const col = clamp(term.cursorCol, 0, term.cols - 1);
      const padded = line.padEnd(col + 1, " ");
      const before = padded.slice(0, col);
      const under = padded[col] === " " ? "&nbsp;" : escapeHtml(padded[col]);
      const after = padded.slice(col + 1);
      return `${escapeHtml(before)}<span class="terminal-caret-inline">${under}</span>${escapeHtml(after)}`;
    })
    .join("\n");
}

function renderNetworkChart() {
  const history = state.metricsHistory || [];
  const metrics = state.metrics;
  if (!metrics || !history.length) return `<div class="tiny" style="padding:12px;">${t("Waiting for network data...")}</div>`;

  const devices = (metrics.netDevices || []).filter((d) => d.name !== "lo");
  if (!devices.length) return `<div class="tiny" style="padding:12px;">${t("No network devices found")}</div>`;

  let iface = state.selectedNetInterface;
  if (!iface || !devices.find((d) => d.name === iface)) {
    iface = devices[0].name;
    state.selectedNetInterface = iface;
  }

  const lastPoint = history[history.length - 1];
  const speeds = lastPoint?.netSpeeds?.[iface] || { rxSpeed: 0, txSpeed: 0 };

  let maxSpeed = 1024;
  for (const pt of history) {
    const sp = pt.netSpeeds?.[iface];
    if (sp) {
      maxSpeed = Math.max(maxSpeed, sp.rxSpeed, sp.txSpeed);
    }
  }
  maxSpeed *= 1.2;

  let maxLat = 10;
  for (const pt of history) {
    maxLat = Math.max(maxLat, pt.latency);
  }
  maxLat *= 1.2;

  const w = 240;
  const hNet = 60;
  const hLat = 40;

  let rxPoints = "";
  let txPoints = "";
  let latPoints = "";
  
  // 计算折线图多边形区域坐标，从左下角开始
  let rxPoly = `0,${hNet} `;
  let txPoly = `0,${hNet} `;
  let latPoly = `0,${hLat} `;

  for (let i = 0; i < history.length; i++) {
    const pt = history[i];
    const sp = pt.netSpeeds?.[iface] || { rxSpeed: 0, txSpeed: 0 };
    
    // 根据最大点数（60）分配横坐标
    // 除以59是为了让最后一个点刚好靠在最右侧边缘
    const x = (i / 59) * w;
    const yRx = hNet - (sp.rxSpeed / maxSpeed) * hNet;
    const yTx = hNet - (sp.txSpeed / maxSpeed) * hNet;
    const yLat = hLat - (pt.latency / maxLat) * hLat;

    rxPoints += `${x},${yRx} `;
    txPoints += `${x},${yTx} `;
    latPoints += `${x},${yLat} `;
    
    rxPoly += `${x},${yRx} `;
    txPoly += `${x},${yTx} `;
    latPoly += `${x},${yLat} `;
  }
  
  const lastX = history.length > 0 ? ((history.length - 1) / 59) * w : 0;
  rxPoly += `${lastX},${hNet}`;
  txPoly += `${lastX},${hNet}`;
  latPoly += `${lastX},${hLat}`;

  return `
    <div class="net-chart-header">
      <div class="net-speeds">
        <span class="tx-color">↑ ${humanBytes(speeds.txSpeed)}/s</span>
        <span class="rx-color">↓ ${humanBytes(speeds.rxSpeed)}/s</span>
      </div>
      ${renderMdSelect("netIfaceSelect", devices.map((d) => ({ value: d.name, label: d.name })), iface, { compact: true, action: "change-net-iface" })}
    </div>
    <div class="net-chart-container">
      <div class="net-chart-bg">
        <div class="net-chart-label">${humanBytes(maxSpeed)}/s</div>
        <div class="net-chart-label">${humanBytes(maxSpeed/2)}/s</div>
        <div class="net-chart-label">0 B/s</div>
      </div>
      <svg class="net-chart-svg" viewBox="0 0 ${w} ${hNet}" preserveAspectRatio="none">
        <!-- 图表阴影区域 -->
        <polygon points="${rxPoly}" fill="var(--chart-rx-fill)" />
        <polygon points="${txPoly}" fill="var(--chart-tx-fill)" />
        <!-- 图表核心线条 -->
        <polyline points="${rxPoints}" fill="none" stroke="var(--chart-rx)" stroke-width="1.5" />
        <polyline points="${txPoints}" fill="none" stroke="var(--chart-tx)" stroke-width="1.5" />
      </svg>
    </div>
    <div class="lat-chart-container">
      <div class="net-chart-bg">
        <div class="net-chart-label">${Math.round(maxLat)} ms</div>
        <div class="net-chart-label">0 ms</div>
      </div>
      <svg class="lat-chart-svg" viewBox="0 0 ${w} ${hLat}" preserveAspectRatio="none">
        <polygon points="${latPoly}" fill="var(--chart-lat-fill)" />
        <polyline points="${latPoints}" fill="none" stroke="var(--chart-lat)" stroke-width="1.5" />
      </svg>
      <div class="lat-value">${lastPoint?.latency || 0} ms</div>
    </div>
  `;
}

function renderMonitor() {
  const host = state.activeHost;
  const metrics = state.metrics;
  if (!host) return "";
  return `
    <div class="metric-card">
      <div class="metric-title">${escapeHtml(host.name)}</div>
      <div class="kv"><span>${t("Host")}</span><strong>${escapeHtml(host.username)}@${escapeHtml(host.host)}</strong></div>
      <div class="kv"><span>${t("Connected")}</span><strong>${escapeHtml(state.connection?.connectedAt || "-")}</strong></div>
      <div class="kv"><span>${t("OS")}</span><strong>${escapeHtml(metrics?.os || state.connection?.banner || "-")}</strong></div>
    </div>
    <div class="metric-card">
      <div class="metric-title">${t("System")}</div>
      ${barRow(t("CPU"), metrics?.cpuPercent || 0, `${Math.round(metrics?.cpuPercent || 0)}%`)}
      ${barRow(t("Memory"), percent(metrics?.memUsed || 0, metrics?.memTotal || 0), `${humanBytes(metrics?.memUsed || 0)} / ${humanBytes(metrics?.memTotal || 0)}`)}
      ${barRow(t("Swap"), percent(metrics?.swapUsed || 0, metrics?.swapTotal || 0), `${humanBytes(metrics?.swapUsed || 0)} / ${humanBytes(metrics?.swapTotal || 0)}`)}
      <div class="kv"><span>${t("Load")}</span><strong>${(metrics?.load || [0, 0, 0]).map((n) => Number(n).toFixed(2)).join(", ")}</strong></div>
      <div class="kv"><span>${t("Uptime")}</span><strong>${formatDuration(metrics?.uptimeSeconds || 0)}</strong></div>
    </div>
    <div class="metric-card network-chart-card">
      ${renderNetworkChart()}
    </div>
    <div class="metric-card">
      <div class="metric-title">${t("Mounts")}</div>
      ${(metrics?.disks || [])
        .slice(0, 8)
        .map((disk) => `<div class="kv"><span>${escapeHtml(disk.mount)}</span><strong>${humanBytes(disk.used)} / ${humanBytes(disk.total)}</strong></div>`)
        .join("") || `<div class="tiny">${t("Waiting for disk data...")}</div>`}
    </div>
  `;
}

function renderUploadPrompts() {
  const dirty = state.watchedFiles.filter((file) => file.dirty);
  return dirty
    .map(
      (file) => `
      <div class="upload-strip">
        <span>${t("Local edits detected:")} <strong>${escapeHtml(file.remotePath)}</strong></span>
        <span>
          <button class="btn primary" data-action="upload-file" data-remote-path="${escapeAttr(file.remotePath)}">${t("Upload")}</button>
          <button class="btn ghost" data-action="discard-file" data-remote-path="${escapeAttr(file.remotePath)}">${t("Discard")}</button>
        </span>
      </div>
    `,
    )
    .join("");
}

function renderSftp() {
  const q = state.sftpFilter.trim().toLowerCase();
  const entries = state.remoteEntries.filter((entry) => !q || entry.name.toLowerCase().includes(q));
  return `
    <div class="sftp-toolbar">
      <button class="icon-btn" data-action="sftp-up" title="${t("Parent folder")}">&lt;</button>
      <div class="path-pill">${escapeHtml(state.remotePath)}</div>
      <div class="search"><input id="sftpFilter" value="${escapeAttr(state.sftpFilter)}" placeholder="${t('Filter files...')}" /></div>
      <button class="btn" data-action="create-folder">${t("New Folder")}</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>${t("Name")}</th><th style="width:120px">${t("Size")}</th><th style="width:110px">${t("Kind")}</th><th style="width:160px">${t("Modified")}</th><th style="width:100px">${t("Mode")}</th><th style="width:130px">${t("Owner")}</th></tr>
        </thead>
        <tbody>
          ${
            entries.length
              ? entries.map(renderSftpRow).join("")
              : `<tr><td colspan="6" class="empty">${t("No files loaded.")}</td></tr>`
          }
        </tbody>
      </table>
    </div>
  `;
}

function renderSftpRow(entry) {
  return `
    <tr data-sftp-path="${escapeAttr(entry.path)}" class="${state.sftpSelected.includes(entry.path) ? "selected" : ""}">
      <td><div class="file-name">${fileIcon(entry)} <span class="truncate-text">${escapeHtml(entry.name)}</span></div></td>
      <td>${entry.isDir ? "-" : humanBytes(entry.size)}</td>
      <td>${escapeHtml(entry.extension)}</td>
      <td>${formatTime(entry.modified)}</td>
      <td>${formatMode(entry.permissions)}</td>
      <td>${escapeHtml(entry.owner || "-")}</td>
    </tr>
  `;
}

// Material Design icons (24px): folder, shortcut, insert_drive_file.
function fileIcon(entry) {
  if (entry.isLink) {
    return `<span class="file-icon link" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M21 11l-6-6v5H8c-2.76 0-5 2.24-5 5v4h2v-4c0-1.65 1.35-3 3-3h7v5l6-6z"/></svg></span>`;
  }
  if (entry.isDir) {
    return `<span class="file-icon folder" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg></span>`;
  }
  return `<span class="file-icon file" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M6 2c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6H6zm7 7V3.5L18.5 9H13z"/></svg></span>`;
}

/* --------------------------------------------------------------------------
   Snippet packages: named categories for snippets. A snippet belongs to at
   most one package (packageId); "" means the Default category.
   -------------------------------------------------------------------------- */
const SNIPPET_PACKAGES_KEY = "vps-studio.snippetPackages.v1";

function newPackageId() {
  return `pkg-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function loadSnippetPackages() {
  try {
    const parsed = JSON.parse(window.localStorage?.getItem(SNIPPET_PACKAGES_KEY) || "[]");
    return Array.isArray(parsed)
      ? parsed.filter((pkg) => pkg && pkg.id).map((pkg) => ({ id: pkg.id, name: String(pkg.name || "") }))
      : [];
  } catch {
    return [];
  }
}

function persistSnippetPackages() {
  try {
    window.localStorage?.setItem(SNIPPET_PACKAGES_KEY, JSON.stringify(state.snippetPackages));
  } catch (error) {
    pushLog("Snippets", `Save snippet packages failed: ${error}`);
  }
}

function packageById(id) {
  return id ? state.snippetPackages.find((pkg) => pkg.id === id) || null : null;
}

function packageByName(name) {
  const wanted = String(name || "").trim().toLowerCase();
  return wanted ? state.snippetPackages.find((pkg) => pkg.name.trim().toLowerCase() === wanted) || null : null;
}

// Returns the id of the package with this name, creating it when it does not
// exist yet. A blank name means the Default category ("").
function ensurePackageNamed(name) {
  const trimmed = String(name || "").trim();
  if (!trimmed) return "";
  const existing = packageByName(trimmed);
  if (existing) return existing.id;
  const pkg = { id: newPackageId(), name: trimmed };
  state.snippetPackages.push(pkg);
  persistSnippetPackages();
  return pkg.id;
}

// One-time move from the old free-text `package` field to real packages.
function migrateSnippetPackages() {
  let changed = false;
  for (const snippet of state.snippets) {
    if (snippet.package && !snippet.packageId) {
      snippet.packageId = ensurePackageNamed(snippet.package);
      changed = true;
    }
    if ("package" in snippet) {
      delete snippet.package;
      changed = true;
    }
    if (snippet.packageId && !packageById(snippet.packageId)) {
      snippet.packageId = "";
      changed = true;
    }
  }
  if (changed) persistSnippets();
}

function snippetsInPackage(packageId) {
  return state.snippets.filter((snippet) => (snippet.packageId || "") === (packageId || ""));
}

function packageIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16.5 9.4 7.55 4.24"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.29 7 12 12 20.71 7"/><line x1="12" y1="22" x2="12" y2="12"/></svg>`;
}

function packageCountLabel(count) {
  return count === 1 ? t("{0} snippet", count) : t("{0} snippets", count);
}

function packageLabel(pkg) {
  return pkg?.name?.trim() || t("Unnamed package");
}

/* ---------- Snippets page ---------- */

function renderSnippetMenu() {
  return `
    <div class="dropdown-menu wide">
      <button data-action="new-snippet-package">${btnIcon(packageIcon())}<span>${t("New snippet package")}</span></button>
    </div>
  `;
}

function renderPackageCard(pkg) {
  return `
    <article class="mini-card package-card ${state.selectedPackageId === pkg.id ? "active" : ""}" data-package-id="${escapeAttr(pkg.id)}">
      <div class="mini-icon">${packageIcon()}</div>
      <div class="card-content">
        <div class="host-name truncate-text">${escapeHtml(packageLabel(pkg))}</div>
        <div class="host-meta truncate-text">${escapeHtml(packageCountLabel(snippetsInPackage(pkg.id).length))}</div>
      </div>
      <button class="card-edit" title="${t("Edit package")}" data-action="edit-package" data-package-id="${escapeAttr(pkg.id)}">${pencilIcon()}</button>
    </article>
  `;
}

function openPackageDetails(pkg = null) {
  syncFormsToState();
  state.section = "snippets";
  state.editingPackage = pkg ? { id: pkg.id, name: pkg.name, isNew: false } : { id: newPackageId(), name: "", isNew: true };
  state.selectedPackageId = pkg ? pkg.id : null;
  state.detailKind = "package";
  state.detailOpen = true;
  state.editorOpen = false;
  state.editingSnippet = null;
  state.editingSnippetIndex = -1;
  closeMenus();
  state.skipFormSync = true;
  render();
  if (!pkg) requestAnimationFrame(() => document.getElementById("packageName")?.focus());
}

function readPackageDetails() {
  if (!state.editingPackage || !document.getElementById("packageName")) return;
  state.editingPackage.name = rawValue("packageName");
}

function savePackageDetails() {
  readPackageDetails();
  const editing = state.editingPackage;
  if (!editing) return;
  const name = editing.name.trim();
  if (!name) return setStatus(t("Package name is required"));
  const clash = packageByName(name);
  if (clash && clash.id !== editing.id) return setStatus(t("A package named {0} already exists", name));
  const existing = packageById(editing.id);
  if (existing) existing.name = name;
  else state.snippetPackages.push({ id: editing.id, name });
  persistSnippetPackages();
  state.editingPackage = { id: editing.id, name, isNew: false };
  state.selectedPackageId = editing.id;
  setStatus(t("Package saved"));
}

async function removePackage(packageId) {
  const pkg = packageById(packageId);
  if (!pkg) return;
  const members = snippetsInPackage(packageId);
  const confirmed = await requestDeleteConfirmation({
    title: t("Remove package"),
    message: members.length
      ? t("Are you sure you want to remove this package? Its {0} snippets are kept and move to Default.", members.length)
      : t("Are you sure you want to remove this package?"),
    item: { type: "package", title: packageLabel(pkg), subtitle: packageCountLabel(members.length) },
  });
  if (!confirmed) return;
  members.forEach((snippet) => {
    snippet.packageId = "";
  });
  state.snippetPackages = state.snippetPackages.filter((item) => item.id !== packageId);
  if (state.selectedPackageId === packageId) state.selectedPackageId = null;
  if (state.cmdCategory === packageId) state.cmdCategory = "";
  if (state.editingPackage?.id === packageId) closeEditor();
  persistSnippetPackages();
  persistSnippets();
  setStatus(t("Package removed"));
  render();
}

function renderPackageDetails() {
  const pkg = state.editingPackage || { id: "", name: "", isNew: true };
  const members = pkg.isNew ? [] : snippetsInPackage(pkg.id);
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t(pkg.isNew ? "New Package" : "Edit Package")}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t("Close")}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          <h3>${t("General")}</h3>
          <div class="detail-row with-mark">
            <div class="host-mark blue">${packageIcon()}</div>
            <input id="packageName" value="${escapeAttr(pkg.name)}" placeholder="${t("Package name")}" />
          </div>
        </section>
        ${
          pkg.isNew
            ? ""
            : `<section class="details-card">
                <h3>${t("Snippets in this package")}</h3>
                ${
                  members.length
                    ? `<div class="package-members">${members
                        .map(
                          (snippet) => `
                          <button class="package-member" data-action="edit-snippet" data-snippet-id="${escapeAttr(snippet.id)}">
                            <span class="package-member-icon">${snippetIcon()}</span>
                            <span class="package-member-text">
                              <strong class="truncate-text">${escapeHtml(snippetLabel(snippet) || snippet.script)}</strong>
                              ${snippetLabel(snippet) ? `<span class="truncate-text code-font">${escapeHtml(snippet.script)}</span>` : ""}
                            </span>
                          </button>`,
                        )
                        .join("")}</div>`
                    : `<div class="tiny">${t("No snippets in this package yet. Choose this package when editing a snippet.")}</div>`
                }
              </section>`
        }
      </div>
      <div class="details-foot">
        <button class="btn danger ${pkg.isNew ? "hidden" : ""}" data-action="remove-editing-package">${t("Remove")}</button>
        <button class="btn primary wide-action" data-action="save-package">${t("Save Package")}</button>
      </div>
    </aside>
  `;
}

/* ---------- SSH workspace: FinalShell-style command panel ---------- */
const COMMAND_EDITOR_KEY = "vps-studio.commandEditor.v1";

function loadCommandEditorOptions() {
  const defaults = { ctrlEnter: false, clearAfterSend: true, appendCr: true };
  try {
    return { ...defaults, ...JSON.parse(window.localStorage?.getItem(COMMAND_EDITOR_KEY) || "{}") };
  } catch {
    return defaults;
  }
}

function persistCommandEditorOptions() {
  try {
    window.localStorage?.setItem(COMMAND_EDITOR_KEY, JSON.stringify(state.cmdOptions));
  } catch {
    // Options are a convenience; losing them is harmless.
  }
}

function commandCategories() {
  const categories = [{ id: "", name: t("Default"), count: snippetsInPackage("").length }];
  applySort(state.snippetPackages, (pkg) => pkg.name).forEach((pkg) => {
    categories.push({ id: pkg.id, name: packageLabel(pkg), count: snippetsInPackage(pkg.id).length });
  });
  return categories;
}

function renderSessionSnippets() {
  return `
    <div class="cmd-panel">
      ${renderCommandListPane()}
      <section class="cmd-editor-pane">
        <div class="cmd-pane-title">${t("Command editor")}</div>
        <textarea id="commandEditor" class="cmd-editor code-font" spellcheck="false" autocomplete="off" placeholder="${t("Type commands here, then click Send.")}">${escapeHtml(state.cmdEditorText)}</textarea>
        <div class="cmd-actions" id="commandEditorActions">${renderCommandEditorActions()}</div>
      </section>
    </div>
  `;
}

function renderCommandListPane() {
  if (!packageById(state.cmdCategory)) state.cmdCategory = "";
  const categories = commandCategories();
  const snippets = applySort(snippetsInPackage(state.cmdCategory), (snippet) => snippetLabel(snippet) || snippet.script);
  if (!snippets.some((snippet) => snippet.id === state.cmdSelectedSnippetId)) state.cmdSelectedSnippetId = null;
  const list = state.snippets.length
    ? snippets.length
      ? snippets
          .map(
            (snippet) => `
            <div class="cmd-item ${snippet.id === state.cmdSelectedSnippetId ? "selected" : ""}" data-cmd-snippet="${escapeAttr(snippet.id)}" title="${escapeAttr(snippet.script)}">${escapeHtml(snippetLabel(snippet) || snippet.script)}</div>`,
          )
          .join("")
      : `<div class="cmd-empty">${t("No snippets in this category.")}</div>`
    : `<div class="cmd-empty">${t("No snippets saved. Add snippets in the Snippets page.")}</div>`;
  return `
    <section class="cmd-list-pane" id="commandListPane">
      <div class="cmd-categories" role="tablist">
        ${categories
          .map(
            (category) => `
            <button class="cmd-category ${category.id === state.cmdCategory ? "active" : ""}" role="tab" data-cmd-category="${escapeAttr(category.id)}">
              ${groupIcon()}<span class="truncate-text">${escapeHtml(category.name)}</span><span class="cmd-count">${category.count}</span>
            </button>`,
          )
          .join("")}
      </div>
      <div class="cmd-list">${list}</div>
      <div class="cmd-actions">
        <span class="cmd-hint">${t("Double-click a snippet to send it.")}</span>
        <button class="btn primary" data-cmd-send-snippet ${state.cmdSelectedSnippetId && state.activeShellId ? "" : "disabled"}>${t("Send")}</button>
      </div>
    </section>
  `;
}

function renderCommandEditorActions() {
  const options = [
    ["ctrlEnter", t("Send with Ctrl+Enter")],
    null,
    ["clearAfterSend", t("Clear after sending")],
    ["appendCr", t("Append carriage return (CR)")],
  ];
  return `
    <div class="cmd-options-wrap">
      <button class="btn ${state.cmdOptionsOpen ? "primary" : "ghost strong"}" data-cmd-options-toggle aria-expanded="${state.cmdOptionsOpen}">${t("Options")}</button>
      ${
        state.cmdOptionsOpen
          ? `<div class="dropdown-menu cmd-options-menu" role="menu">
              ${options
                .map((option) =>
                  option
                    ? `<button role="menuitemcheckbox" aria-checked="${Boolean(state.cmdOptions[option[0]])}" data-cmd-option="${option[0]}">
                        <span class="cmd-check">${state.cmdOptions[option[0]] ? checkIcon() : ""}</span><span>${escapeHtml(option[1])}</span>
                      </button>`
                    : `<div class="cmd-menu-divider" role="separator"></div>`,
                )
                .join("")}
            </div>`
          : ""
      }
    </div>
    <button class="btn primary" data-cmd-send-editor ${state.activeShellId ? "" : "disabled"}>${t("Send")}</button>
  `;
}

function selectCommandSnippet(id) {
  state.cmdSelectedSnippetId = id;
  document.querySelectorAll(".cmd-panel [data-cmd-snippet]").forEach((el) => {
    el.classList.toggle("selected", el.dataset.cmdSnippet === id);
  });
  const send = document.querySelector("[data-cmd-send-snippet]");
  if (send) send.disabled = !state.activeShellId;
}

// Repaint pieces of the panel in place: a full render() would rebuild the
// terminal area and lose the editor's caret.
function repaintCommandList() {
  const pane = document.getElementById("commandListPane");
  if (pane) pane.outerHTML = renderCommandListPane();
}

function repaintCommandEditorActions() {
  const actions = document.getElementById("commandEditorActions");
  if (actions) actions.innerHTML = renderCommandEditorActions();
}

async function sendCommandText(text, { appendCr }) {
  if (!state.activeShellId) return false;
  // Each line of a multi-line command is submitted like pressing Enter.
  let data = String(text || "").replace(/\r\n|\n/g, "\r");
  if (!data.trim()) return false;
  if (appendCr && !data.endsWith("\r")) data += "\r";
  const host = state.activeHost || { name: "Local Terminal", username: "local" };
  data
    .split("\r")
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      pushLog("Command", line, host);
      recordShellHistory(line);
    });
  await sendShellInput(data);
  return true;
}

async function sendSelectedSnippet() {
  const snippet = state.snippets.find((item) => item.id === state.cmdSelectedSnippetId);
  if (snippet) await sendCommandText(snippet.script, { appendCr: true });
}

async function sendCommandEditor() {
  const editor = document.getElementById("commandEditor");
  const text = editor ? editor.value : state.cmdEditorText;
  const sent = await sendCommandText(text, { appendCr: state.cmdOptions.appendCr });
  if (sent && state.cmdOptions.clearAfterSend) {
    state.cmdEditorText = "";
    if (editor) editor.value = "";
  }
  editor?.focus();
}

// "Remove" beside the snippet's package field: back to Default on save.
function bindPackageFieldEvents() {
  const sync = () => {
    const input = document.getElementById("snippetPackage");
    const button = document.querySelector("[data-package-remove]");
    if (input && button) button.hidden = !input.value.trim();
  };
  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-package-remove]")) return;
    const input = document.getElementById("snippetPackage");
    if (!input) return;
    input.value = "";
    input.closest(".md-combo")?.classList.remove("has-value");
    if (state.editingSnippet) state.editingSnippet.packageName = "";
    closeCombo();
    sync();
  });
  document.addEventListener("input", (event) => {
    if (event.target.id === "snippetPackage") sync();
  });
  document.addEventListener("change", (event) => {
    if (event.target.id === "snippetPackage") sync();
  });
}

function bindCommandPanelEvents() {
  document.addEventListener("click", (event) => {
    const panel = event.target.closest(".cmd-panel");
    if (state.cmdOptionsOpen && !event.target.closest(".cmd-options-wrap")) {
      state.cmdOptionsOpen = false;
      repaintCommandEditorActions();
    }
    if (!panel) return;
    const category = event.target.closest("[data-cmd-category]");
    if (category) {
      state.cmdCategory = category.dataset.cmdCategory;
      state.cmdSelectedSnippetId = null;
      return repaintCommandList();
    }
    const item = event.target.closest("[data-cmd-snippet]");
    if (item) return selectCommandSnippet(item.dataset.cmdSnippet);
    if (event.target.closest("[data-cmd-send-snippet]")) return sendSelectedSnippet();
    if (event.target.closest("[data-cmd-send-editor]")) return sendCommandEditor();
    if (event.target.closest("[data-cmd-options-toggle]")) {
      state.cmdOptionsOpen = !state.cmdOptionsOpen;
      return repaintCommandEditorActions();
    }
    const option = event.target.closest("[data-cmd-option]");
    if (option) {
      const key = option.dataset.cmdOption;
      state.cmdOptions[key] = !state.cmdOptions[key];
      persistCommandEditorOptions();
      repaintCommandEditorActions();
    }
  });

  document.addEventListener("dblclick", (event) => {
    const item = event.target.closest(".cmd-panel [data-cmd-snippet]");
    if (!item) return;
    selectCommandSnippet(item.dataset.cmdSnippet);
    sendSelectedSnippet();
  });

  document.addEventListener("input", (event) => {
    if (event.target.id === "commandEditor") state.cmdEditorText = event.target.value;
  });

  document.addEventListener("keydown", (event) => {
    if (event.target.id !== "commandEditor") return;
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey) && state.cmdOptions.ctrlEnter) {
      event.preventDefault();
      sendCommandEditor();
    }
  });
}

function renderDetailsPanel() {
  if (state.detailKind === "generateKey") return renderGenerateKeyDetails();
  if (state.detailKind === "key") return renderKeyDetails();
  if (state.detailKind === "identity") return renderIdentityDetails();
  if (state.detailKind === "snippet") return renderSnippetDetails();
  if (state.detailKind === "package") return renderPackageDetails();
  if (state.detailKind === "shellHistory") return renderShellHistoryPanel();
  if (state.detailKind === "group") return renderGroupDetails();
  return renderHostDetails();
}

function renderIdentityAuthFields(ident) {
  const isKey = isKeyAuth(ident.auth);
  return `
    <div class="auth-switch detail-switch">
      <button class="btn ${isKey ? "primary" : ""}" data-action="ident-auth-key">${keySmallIcon()} ${t("Key")}</button>
      <button class="btn ${!isKey ? "primary" : ""}" data-action="ident-auth-password">${passwordIcon()} ${t("Password")}</button>
    </div>
    ${
      isKey
        ? `${renderKeySelect("editIdentKeyId", ident.auth)}
           ${detailPasswordInput("Key passphrase", "editIdentKeyPassphrase", ident.auth.passphrase || "")}`
        : `${detailPasswordInput("Password", "editIdentPassword", ident.auth.password || "")}`
    }
  `;
}

function unlinkIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m18.84 12.25 1.72-1.71h-.02a5.004 5.004 0 0 0-.12-7.07 5.006 5.006 0 0 0-6.95 0l-1.72 1.71"/><path d="m5.17 11.67-1.71 1.71a5.004 5.004 0 0 0 .12 7.07 5.006 5.006 0 0 0 6.95 0l1.71-1.71"/><line x1="8" y1="2" x2="8" y2="5"/><line x1="2" y1="8" x2="5" y2="8"/><line x1="16" y1="19" x2="16" y2="22"/><line x1="19" y1="16" x2="22" y2="16"/></svg>`;
}

function renderIdentityDetails() {
  const ident = state.editingIdentity || emptyIdentity();
  const title = ident.label || ident.username ? "Edit Identity" : "New Identity";
  
  const linkedHosts = state.hosts.filter((h) => h.identityId === ident.id);
  const linkedSection = linkedHosts.length > 0 ? `
    <div class="divider"></div>
    <div style="margin-bottom:8px;"><strong style="font-size:14px; color:var(--text);">${t("Linked to")}</strong></div>
    <div class="page-grid" style="gap:12px;">
      ${linkedHosts.map((h) => `
        <article class="mini-card host-card" style="padding-right: 16px;">
          <div class="mini-icon" style="background: var(--md-sys-color-tertiary-container); color: var(--md-sys-color-on-tertiary-container);">${hostMarkIcon()}</div>
          <div class="card-content">
            <div class="host-name truncate-text">${escapeHtml(h.name || h.host)}</div>
            <div class="host-meta truncate-text">ssh, ${escapeHtml(h.username || "root")}</div>
          </div>
          <button class="icon-btn unbind-btn" style="opacity:0; transition:opacity 0.2s;" title="${t('Unbind')}" data-action="unlink-identity-host" data-host-id="${escapeAttr(h.id)}">${unlinkIcon()}</button>
        </article>
      `).join("")}
    </div>
    <style>
      .mini-card:hover .unbind-btn { opacity: 1 !important; }
    </style>
  ` : "";

  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t(title)}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t('Close')}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          ${renderKeyTextInput(t("Label"), "editIdentLabel", ident.label, false)}
          ${renderKeyTextInput(t("Username") + " *", "editIdentUsername", ident.username)}
          ${renderIdentityAuthFields(ident)}
        </section>
        ${ident.id && state.editingIdentityIndex >= 0 ? linkedSection : ""}
      </div>
      <div class="details-foot">
        <button class="btn ghost" data-action="close-editor">${t("Close")}</button>
        <button class="btn primary wide-action" data-action="save-identity">${t("Save")}</button>
      </div>
    </aside>
  `;
}

function renderShellHistoryPanel() {
  const history = state.shellHistory;
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t("Shell History")}</h2>
        </div>
        <button class="icon-btn quiet" title="${t('Close')}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll shell-history-scroll">
        ${history.length
          ? history.map((entry, index) => renderShellHistoryItem(entry, index)).join("")
          : `<div class="empty">${t("No commands recorded yet.")}</div>`
        }
      </div>
    </aside>
  `;
}

function renderShellHistoryItem(entry, index) {
  const isSaving = state.shellHistorySavingIndex === index;
  if (isSaving) {
    return `
      <div class="shell-history-item saving">
        <div class="shell-history-label-row">
          <input id="historyLabel-${index}" class="shell-history-label-input" placeholder="${t("Set a label")}" autofocus />
          <button class="btn primary shell-history-done-btn" data-action="history-done" data-index="${index}">${t("Done")}</button>
        </div>
        <div class="shell-history-cmd">${escapeHtml(entry.command)}</div>
      </div>
    `;
  }
  return `
    <div class="shell-history-item" data-history-index="${index}">
      <div class="shell-history-cmd">${escapeHtml(entry.command)}</div>
      <button class="btn primary shell-history-save-btn" data-action="history-save" data-index="${index}">${t("Save")}</button>
    </div>
  `;
}

function renderSnippetDetails() {
  const snippet = state.editingSnippet || emptySnippet();
  const isEdit = state.editingSnippetIndex >= 0;
  const title = isEdit ? "Edit Snippet" : "New Snippet";
  const snippetPackageName = snippet.packageName ?? packageById(snippet.packageId)?.name ?? "";
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t(title)}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t("Close")}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          <div class="detail-field">
            <label>${t("Action description")}</label>
            <input id="snippetName" value="${escapeAttr(snippet.name || "")}" placeholder="${t("Example: check network load")}" />
          </div>
          <div class="detail-field">
            <label>${t("Package")}</label>
            <div class="package-field-row">
              ${renderMdCombo(
                "snippetPackage",
                applySort(state.snippetPackages, (pkg) => pkg.name).map((pkg) => ({ value: pkg.name, label: pkg.name })),
                snippetPackageName,
                { placeholder: t("Add a Package"), icon: packageIcon(), clearable: false },
              )}
              <button type="button" class="btn ghost package-remove-btn" data-package-remove ${snippetPackageName ? "" : "hidden"}>${t("Remove")}</button>
            </div>
            <div class="field-hint">${t("Pick a package, or type a new name to create one.")}</div>
          </div>
          <div class="detail-field">
            <label>${t("Script *")}</label>
            <textarea id="snippetScript" class="snippet-script-textarea">${escapeHtml(snippet.script || "")}</textarea>
          </div>
        </section>
      </div>
      <div class="details-foot">
        <button class="btn danger ${isEdit ? "" : "hidden"}" data-action="remove-editing-snippet">${t("Remove")}</button>
        <button class="btn primary wide-action" data-action="save-snippet">${t("Save Snippet")}</button>
      </div>
    </aside>
  `;
}

function renderKeyDetails() {
  const key = state.editingKey || emptyKey();
  const title = key.label || key.privateKey || key.publicKey ? "Edit Key" : "New Key";
  const importBlock =
    title === "New Key"
      ? `
        <section class="details-card">
          <button class="key-dropzone" data-action="import-key-file">
            <span>+</span>
            <strong>${t("Drag and drop a private key file to import")}</strong>
          </button>
          <button class="btn primary wide-action" data-action="import-key-file">${t("Import from key file")}</button>
          <input id="keyFileInput" class="hidden-file-input" type="file" />
        </section>
      `
      : "";
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t(title)}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t('Close')}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          ${renderKeyTextInput(t("Label"), "keyLabel", key.label, labelInvalid(key))}
          ${renderKeyTextArea(t("Private key") + " *", "keyPrivate", key.privateKey, "privateKey", privateKeyInvalid(key))}
          ${renderKeyTextArea(t("Public key"), "keyPublic", key.publicKey, "publicKey", publicKeyInvalid(key))}
        </section>
        ${importBlock}
      </div>
      <div class="details-foot">
        <button class="btn ghost" data-action="close-editor">${t("Close")}</button>
        <button class="btn primary wide-action" data-action="save-key">${t("Save Key")}</button>
      </div>
    </aside>
  `;
}

function renderGenerateKeyDetails() {
  const generator = { ...emptyKeyGenerator(), ...(state.keyGenerator || {}) };
  const type = generator.keyType || "ed25519";
  const note = type === "rsa" ? t("Legacy devices") : type === "ecdsa" ? "OpenSSH 5.7+" : "OpenSSH 6.5+";
  const ecdsaBlock =
    type === "ecdsa"
      ? renderGenerateSizeSelector(t("Elliptic curve size (bits)"), "generate-ecdsa-size", [521, 384, 256], generator.ecdsaSize)
      : "";
  const rsaBlock =
    type === "rsa" ? renderGenerateSizeSelector(t("Key size (bits)"), "generate-rsa-size", [4096, 2048, 1024], generator.rsaSize) : "";
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t("Generate Key")}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t('Close')}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          <div class="detail-field">
            <input id="generateKeyLabel" value="${escapeAttr(generator.label || "")}" placeholder="${t('Label')}" />
          </div>
          <div class="detail-field">
            <label>${t("Key type")}</label>
            <div class="segmented-control">
              ${renderGenerateSegment("ED25519", "ed25519", type)}
              ${renderGenerateSegment("ECDSA", "ecdsa", type)}
              ${renderGenerateSegment("RSA", "rsa", type)}
            </div>
            <div class="generate-note">${note}</div>
          </div>
          ${ecdsaBlock}
          ${rsaBlock}
        </section>
        <section class="details-card passphrase-card">
          <div class="detail-field">
            <input value="" placeholder="${t('Passphrase')}" disabled />
          </div>
          <div class="switch-row muted-row">
            <span>${t("Save passphrase")}</span>
            <span class="switch off"></span>
          </div>
        </section>
      </div>
      <div class="details-foot">
        <button class="btn primary wide-action ${state.keyGenerating ? "loading" : ""}" data-action="generate-key-save" ${state.keyGenerating ? "disabled" : ""}>
          ${state.keyGenerating ? t("Generating...") : t("Generate")}
        </button>
      </div>
    </aside>
  `;
}

function renderGenerateSegment(label, value, activeValue) {
  return `<button class="${activeValue === value ? "active" : ""}" data-action="generate-key-type" data-key-type="${escapeAttr(value)}">${escapeHtml(label)}</button>`;
}

function renderGenerateSizeSelector(label, action, values, activeValue) {
  return `
    <div class="detail-field generate-size-field">
      <label>${escapeHtml(label)}</label>
      <div class="segmented-control">
        ${values
          .map(
            (value) =>
              `<button class="${Number(activeValue) === value ? "active" : ""}" data-action="${action}" data-size="${value}">${value}</button>`,
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderKeyTextInput(label, id, value, invalid = false) {
  return `
    <div class="detail-field ${invalid ? "invalid" : ""}">
      <label>${escapeHtml(label)}</label>
      <input id="${id}" value="${escapeAttr(value ?? "")}" />
      ${invalid ? `<div class="field-error">${t("Incorrect format")}</div>` : ""}
    </div>
  `;
}

function renderKeyTextArea(label, id, value, field, invalid = false) {
  const hasValue = Boolean(String(value || "").trim());
  return `
    <div class="detail-field ${invalid ? "invalid" : ""}">
      <label>${escapeHtml(label)}</label>
      <div class="key-textarea-wrap">
        <textarea id="${id}" class="key-textarea">${escapeHtml(value ?? "")}</textarea>
        <button class="copy-chip ${hasValue ? "" : "empty"}" data-action="copy-key-field" data-field="${escapeAttr(field)}">${t("Copy")}</button>
      </div>
      ${invalid ? `<div class="field-error">${t("Incorrect format")}</div>` : ""}
    </div>
  `;
}

function renderHostIdentityMenu() {
  return `
    <div class="dropdown-menu identity-suggest">
      ${state.identities.map((ident) => {
        const sub = [ident.username, ident.label?.trim()].filter(Boolean).join(", ");
        return `
        <button data-action="select-host-identity" data-identity-id="${escapeAttr(ident.id)}">
          <span class="identity-suggest-icon">${identityIcon()}</span>
          <span class="identity-suggest-text">
            <strong class="truncate-text">${escapeHtml(identityLabel(ident))}</strong>
            ${sub ? `<span class="truncate-text">${escapeHtml(sub)}</span>` : ""}
          </span>
        </button>
      `;
      }).join("")}
    </div>
  `;
}

function renderHostDetails() {
  const host = state.editingHost || emptyHost();
  const title = state.editingIndex >= 0 ? "Host Details" : "New Host";
  const groupOptions = allGroupPaths().map((group) => ({ value: group, label: group }));
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t(title)}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t("Close")}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          <h3>${t("Address")}</h3>
          <div class="detail-row with-mark">
            <div class="host-mark" style="background: ${osIcon(host.os).color};">${osIcon(host.os).svg}</div>
            <input id="editHost" value="${escapeAttr(host.host)}" placeholder="${t("Host or IP address")}" />
          </div>
        </section>
        <section class="details-card">
          <h3>${t("General")}</h3>
          ${detailInput(t("Name"), "editName", host.name)}
          <div class="detail-field">
            <label>${t("Group")}</label>
            ${renderMdCombo("editGroup", groupOptions, host.group, { placeholder: t("Group"), icon: groupIcon() })}
          </div>
          ${detailInput(t("Default SFTP path"), "editDefaultPath", host.defaultPath || "/root")}
        </section>
        <section class="details-card">
          <div class="port-row">
            <strong>${t("SSH on")}</strong>
            <input id="editPort" value="${escapeAttr(host.port)}" inputmode="numeric" />
            <strong>${t("port")}</strong>
          </div>
          <div class="divider"></div>
          <h3>${t("Credentials")}</h3>
          ${
            host.identityId
              ? `
                <div class="identity-anchor">
                <div class="identity-box" style="position:relative; display:flex; align-items:center; background: var(--md-sys-color-surface-container-high); padding:8px 12px; border-radius: var(--md-sys-shape-corner-medium); border: 1px solid var(--md-sys-color-primary); cursor:pointer;" data-action="toggle-host-identity-menu">
                  <div style="color: var(--md-sys-color-primary); margin-right:12px; width:24px; height:24px;">${identityIcon()}</div>
                  <div style="flex:1;">
                    <strong style="color:var(--text); font-size:13px; display:block;">${escapeHtml(identityLabel(state.identities.find(i => i.id === host.identityId)))}</strong>
                    <span style="color:var(--muted); font-size:12px;">${t("Identity")}</span>
                  </div>
                  <button class="icon-btn quiet clear-ident-btn" style="opacity:0; transition:opacity 0.2s; padding:4px;" title="${t("Clear identity")}" data-action="clear-host-identity">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                  </button>
                </div>
                ${state.hostIdentityMenuOpen ? renderHostIdentityMenu() : ""}
                </div>
                <style>.identity-box:hover .clear-ident-btn { opacity: 1 !important; }</style>
              `
              : `
                <div class="detail-field">
                  <label>${t("Username")}</label>
                  <div class="identity-anchor">
                    <input id="editUsername" value="${escapeAttr(host.username)}" autocomplete="off" ${state.identities.length > 0 ? 'data-action="toggle-host-identity-menu"' : ""} />
                    ${state.hostIdentityMenuOpen && state.identities.length > 0 ? renderHostIdentityMenu() : ""}
                  </div>
                </div>
                ${renderHostAuthFields(host)}
              `
          }
        </section>
      </div>
      <div class="details-foot">
        <button class="btn danger ${state.editingIndex >= 0 ? "" : "hidden"}" data-action="delete-current">${t("Delete")}</button>
        <button class="btn ghost" data-action="close-editor">${t("Cancel")}</button>
        <button class="btn" data-action="save-editor">${t("Save")}</button>
        <button class="btn primary" data-action="save-connect">${t("Connect")}</button>
      </div>
    </aside>
  `;
}

function renderGroupDetails() {
  const group = state.editingGroup || emptyGroupProfile();
  const groupName = normalizeGroupPath(group.originalName || group.name);
  const title = allGroupPaths().includes(groupName) ? "Group Details" : "New Group";
  const parent = parentGroupPath(group.name) || "";
  const label = groupLabel(group.name);
  const parentOptions = groupParentOptions(group.originalName || group.name);
  return `
    <aside class="details-panel">
      <div class="details-head">
        <div>
          <h2>${t(title)}</h2>
          <div class="details-sub">${t("Personal vault")}</div>
        </div>
        <button class="icon-btn quiet" title="${t("Close")}" data-action="close-editor">${closeIcon()}</button>
      </div>
      <div class="details-scroll">
        <section class="details-card">
          <h3>${t("General")}</h3>
          <div class="detail-row with-mark">
            <div class="host-mark blue">${groupIcon()}</div>
            <input id="groupName" value="${escapeAttr(label)}" placeholder="${t('Group name')}" />
          </div>
          <div class="detail-field">
            <label>${t("Parent Group")}</label>
            ${renderMdCombo("groupParent", parentOptions, parent, { placeholder: t("All hosts"), icon: groupIcon() })}
          </div>
        </section>
        <section class="details-card">
          <div class="switch-row">
            <div>
              <h3>${t("Credentials")}</h3>
              <span>${t("Apply to hosts in this group")}</span>
            </div>
            <label class="toggle">
              <input id="groupUseCredentials" type="checkbox" ${group.useCredentials ? "checked" : ""} />
              <span></span>
            </label>
          </div>
          <div class="${group.useCredentials ? "" : "disabled-block"}">
            <div class="port-row">
              <strong>${t("SSH on")}</strong>
              <input id="groupPort" value="${escapeAttr(group.port)}" inputmode="numeric" ${group.useCredentials ? "" : "disabled"} />
              <strong>${t("port")}</strong>
            </div>
            <div class="divider"></div>
            ${detailInput(t("Username"), "groupUsername", group.username || "root", group.useCredentials ? "" : "disabled")}
            ${renderGroupAuthFields(group)}
          </div>
        </section>
      </div>
      <div class="details-foot">
        <button class="btn ghost" data-action="close-editor">${t("Cancel")}</button>
        <button class="btn primary wide-action" data-action="save-group">${t("Save Group")}</button>
      </div>
    </aside>
  `;
}

function detailInput(label, id, value, attrs = "") {
  return `
    <div class="detail-field">
      <label>${escapeHtml(label)}</label>
      <input id="${id}" value="${escapeAttr(value ?? "")}" ${attrs} />
    </div>
  `;
}

function renderHostAuthFields(host) {
  const isKey = isKeyAuth(host.auth);
  return `
    <div class="auth-switch detail-switch">
      <button class="btn ${isKey ? "primary" : ""}" data-action="auth-key">${keySmallIcon()} ${t("Key")}</button>
      <button class="btn ${!isKey ? "primary" : ""}" data-action="auth-password">${passwordIcon()} ${t("Password")}</button>
    </div>
    ${
      isKey
        ? `${renderKeySelect("editKeyId", host.auth)}
           ${detailPasswordInput("Key passphrase", "editKeyPassphrase", host.auth.passphrase || "")}`
        : `${detailPasswordInput("Password", "editPassword", host.auth.password || "")}`
    }
  `;
}

function renderGroupAuthFields(group) {
  const isKey = isKeyAuth(group.auth);
  const disabled = group.useCredentials ? "" : "disabled";
  return `
    <div class="auth-switch detail-switch">
      <button class="btn ${isKey ? "primary" : ""}" data-action="group-auth-key" ${disabled}>${keySmallIcon()} ${t("Key")}</button>
      <button class="btn ${!isKey ? "primary" : ""}" data-action="group-auth-password" ${disabled}>${passwordIcon()} ${t("Password")}</button>
    </div>
    ${
      isKey
        ? `${renderKeySelect("groupKeyId", group.auth, disabled)}
           ${detailPasswordInput("Key passphrase", "groupKeyPassphrase", group.auth.passphrase || "", disabled)}`
        : `${detailPasswordInput("Password", "groupPassword", group.auth.password || "", disabled)}`
    }
  `;
}

function detailPasswordInput(label, id, value, attrs = "") {
  return `
    <div class="detail-field">
      <label>${escapeHtml(t(label))}</label>
      <input id="${id}" type="password" value="${escapeAttr(value ?? "")}" ${attrs} />
    </div>
  `;
}

function field(label, id, value, extra = "", password = false) {
  return `
    <div class="field ${extra}">
      <label>${label}</label>
      <input id="${id}" ${password ? 'type="password"' : ""} value="${escapeAttr(value ?? "")}" />
    </div>
  `;
}

function readKeyDetails() {
  if (!state.editingKey || !document.getElementById("keyLabel")) return;
  const key = normalizeKey({
    ...state.editingKey,
    label: rawValue("keyLabel"),
    privateKey: rawValue("keyPrivate"),
    publicKey: rawValue("keyPublic"),
  });
  state.editingKey = key;
}

async function copyKeyField(fieldName) {
  readKeyDetails();
  const text = state.editingKey?.[fieldName] || "";
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    setStatus(t("Copied key field"));
  } catch {
    setStatus(t("Copy failed"));
  }
}

function importKeyFile(file) {
  if (!file) return;
  if (!state.editingKey) openKeyDetails();
  const reader = new FileReader();
  reader.onload = () => {
    const key = normalizeKey({
      ...state.editingKey,
      label: file.name,
      privateKey: String(reader.result || ""),
    });
    state.editingKey = key;
    state.skipFormSync = true;
    saveKeyDetails({ readForm: false });
    setStatus(t("Imported {0}", file.name));
  };
  reader.onerror = () => setStatus(t("Import failed: {0}", reader.error?.message || t("file read error")));
  reader.readAsText(file);
}

function readIdentityForm() {
  if (!state.editingIdentity || !document.getElementById("editIdentLabel")) return;
  state.editingIdentity.label = rawValue("editIdentLabel");
  state.editingIdentity.username = rawValue("editIdentUsername");
  if (isKeyAuth(state.editingIdentity.auth)) {
    state.editingIdentity.auth.keyId = rawValue("editIdentKeyId");
    state.editingIdentity.auth.passphrase = rawValue("editIdentKeyPassphrase");
  } else {
    state.editingIdentity.auth.password = rawValue("editIdentPassword");
  }
}

function selectCard(type, id) {
  state.selectedHostId = type === "host" ? id : null;
  state.selectedGroup = type === "group" ? id : null;
  state.selectedKeyId = type === "key" ? id : null;
  state.selectedIdentityId = type === "identity" ? id : null;
  state.selectedSnippetId = type === "snippet" ? id : null;
  state.selectedPackageId = type === "package" ? id : null;
  state.selectedKnownHostId = type === "known_host" ? id : null;
}

function bindEvents() {
  document.querySelectorAll("[data-action]").forEach((element) => {
    element.addEventListener("click", async (event) => {
      event.stopPropagation();
      const action = element.dataset.action;
      
      if (!action.startsWith("toggle-") && !action.startsWith("ctx-") && !element.closest(".dropdown-menu") && !element.closest(".context-menu")) {
        closeMenus();
      }

      switch (action) {
      case "close-all-menus":
        closeMenus();
        render();
        break;
      case "cancel-delete-dialog":
        resolveDeleteConfirmation(false);
        break;
      case "confirm-delete-dialog":
        resolveDeleteConfirmation(true);
        break;
        case "dashboard":
          state.view = "dashboard";
          render();
          break;
        case "session-tab":
          if (state.sessionKind === "ssh" && state.activeHost) state.view = "session";
          render({ terminalBottom: true, focusCommand: true });
          break;
        case "local-terminal-tab":
          if (state.sessionKind === "local" && state.activeShellId) state.view = "localTerminal";
          render({ terminalBottom: true, focusCommand: true });
          break;
        case "disconnect":
          await disconnect();
          break;
        case "nav":
          state.section = element.dataset.section;
          state.openedPackageId = null;
          state.search = "";
          state.showSearch = false;
          state.sortMenuOpen = false;
          state.detailOpen = false;
          state.detailKind = null;
          state.editingHost = null;
          state.editingGroup = null;
          state.editingKey = null;
          state.editingIndex = -1;
          state.editingKeyIndex = -1;
          state.keyGenerator = null;
          state.keyGenerating = false;
          closeMenus();
          render();
          break;
        case "toggle-logs-sort":
          state.logsSortAsc = !state.logsSortAsc;
          render();
          break;
        case "toggle-host-menu":
          state.hostMenuOpen = !state.hostMenuOpen;
          state.keyMenuOpen = false;
          render();
          break;
        case "toggle-key-menu":
          state.keyMenuOpen = !state.keyMenuOpen;
          state.hostMenuOpen = false;
          render();
          break;
        case "toggle-sort-menu":
          state.sortMenuOpen = !state.sortMenuOpen;
          render();
          break;
        case "set-sort-mode":
          state.sortMode = element.dataset.sortMode;
          state.sortMenuOpen = false;
          render();
          break;
        case "toggle-search":
          state.showSearch = !state.showSearch;
          if (!state.showSearch) state.search = "";
          render();
          if (state.showSearch) {
            setTimeout(() => {
              const input = document.getElementById("localSearch");
              if (input) input.focus();
            }, 0);
          }
          break;
        case "new-host":
          openEditor();
          break;
        case "new-key":
          openKeyDetails();
          break;
        case "new-identity":
          openIdentityDetails();
          break;
        case "edit-identity":
          openIdentityDetails(state.identities.find((i) => i.id === element.dataset.identityId));
          break;
        case "new-group":
          await createGroupFromMenu();
          break;
        case "local-terminal":
          await openLocalPowershell();
          break;
        case "edit-host":
          openEditor(state.hosts.find((host) => host.id === element.dataset.hostId));
          break;
        case "edit-group":
          openGroupDetails(element.dataset.group);
          break;
        case "edit-key":
          openKeyDetails(state.keys.find((key) => key.id === element.dataset.keyId));
          break;
        case "open-breadcrumb-group":
          openGroup(element.dataset.group);
          break;
        case "connect-host":
          connectHost(state.hosts.find((host) => host.id === element.dataset.hostId));
          break;
        case "show-all-hosts":
          showAllHosts();
          break;
        case "ctx-connect-host": {
          const host = contextHost();
          state.contextMenu = null;
          if (host) connectHost(host);
          break;
        }
        case "ctx-edit-host": {
          const host = contextHost();
          state.contextMenu = null;
          if (host) openEditor(host);
          break;
        }
        case "ctx-duplicate-host": {
          const host = contextHost();
          state.contextMenu = null;
          if (host) await duplicateHost(host.id);
          break;
        }
        case "ctx-remove-host": {
          const host = contextHost();
          state.contextMenu = null;
          if (host) await deleteHost(host.id);
          break;
        }
        case "ctx-connect-group": {
          const group = contextGroup();
          state.contextMenu = null;
          if (group) connectGroup(group);
          break;
        }
        case "ctx-edit-group": {
          const group = contextGroup();
          state.contextMenu = null;
          if (group) openGroupDetails(group);
          break;
        }
        case "ctx-remove-group": {
          const group = contextGroup();
          state.contextMenu = null;
          if (group) await removeGroup(group);
          break;
        }
        case "ctx-edit-key": {
          const key = contextKey();
          state.contextMenu = null;
          if (key) openKeyDetails(key);
          break;
        }
      case "ctx-remove-key": {
        const key = contextKey();
        state.contextMenu = null;
        if (key) await removeKey(key.id);
        break;
      }
        case "ctx-edit-identity": {
          const identId = state.contextMenu?.id;
          state.contextMenu = null;
          if (identId) openIdentityDetails(state.identities.find(i => i.id === identId));
          break;
        }
      case "ctx-remove-identity": {
        const identId = state.contextMenu?.id;
        const identity = state.identities.find((item) => item.id === identId);
        state.contextMenu = null;
        if (!identity) break;
        const confirmed = await requestDeleteConfirmation({
          title: t("Remove identity"),
          message: t("Are you sure you want to remove this identity?"),
          item: {
            type: "identity",
            title: identity.label || identity.username || t("Unnamed identity"),
            subtitle: identity.username ? `ssh, ${identity.username}` : t("SSH identity"),
          },
        });
        if (!confirmed) break;
        state.identities = state.identities.filter((item) => item.id !== identId);
        if (state.selectedIdentityId === identId) state.selectedIdentityId = null;
        state.hosts.forEach((host) => {
          if (host.identityId === identId) host.identityId = null;
        });
        persistIdentities();
        await saveHosts();
        setStatus(t("Identity removed"));
        render();
        break;
      }
        case "save-identity": {
          if (!state.editingIdentity) break;
          readIdentityForm();
          if (!state.editingIdentity.username.trim()) {
            setStatus(t("Username is required"));
            break;
          }
          if (state.editingIdentityIndex >= 0) {
            state.identities[state.editingIdentityIndex] = clone(state.editingIdentity);
          } else {
            state.identities.unshift(clone(state.editingIdentity));
            state.editingIdentityIndex = 0;
          }
          state.selectedIdentityId = state.editingIdentity.id;
          persistIdentities();
          closeEditor();
          setStatus(t("Identity saved"));
          break;
        }
        case "ident-auth-key":
          if (state.editingIdentity) {
            readIdentityForm();
            state.editingIdentity.auth = { kind: "keyRef", keyId: state.keys[0]?.id || "", passphrase: "" };
            render();
          }
          break;
        case "ident-auth-password":
          if (state.editingIdentity) {
            readIdentityForm();
            state.editingIdentity.auth = { kind: "password", password: "" };
            render();
          }
          break;
        case "unlink-identity-host": {
          const hid = element.dataset.hostId;
          const hostIdx = state.hosts.findIndex(h => h.id === hid);
          if (hostIdx >= 0) {
            state.hosts[hostIdx].identityId = null;
            saveHosts();
            render();
          }
          break;
        }
        case "toggle-host-identity-menu":
          state.hostIdentityMenuOpen = !state.hostIdentityMenuOpen;
          render();
          break;
        case "clear-host-identity":
          if (state.editingHost) {
            state.editingHost.identityId = null;
            render();
          }
          break;
        case "select-host-identity":
          if (state.editingHost) {
            state.editingHost.identityId = element.dataset.identityId;
            state.hostIdentityMenuOpen = false;
            render();
          }
          break;
        case "close-editor":
          closeEditor();
          break;
        case "save-editor":
          readEditor();
          await saveEditor();
          break;
        case "untrusted-close":
          state.untrustedHostPrompt = null;
          state.view = "dashboard";
          render();
          break;
        case "untrusted-continue": {
          const host = state.untrustedHostPrompt.host;
          state.untrustedHostPrompt = null;
          connectHost(host, true);
          break;
        }
        case "untrusted-add": {
          const p = state.untrustedHostPrompt;
          state.untrustedHostPrompt = null;
          setStatus(t("Saving known host..."));
          render();
          try {
            await call("add_known_host", { host: p.host.host, port: p.host.port, fingerprint: p.fingerprint });
            // 更新本地已知主机的状态
            state.knownHosts = state.knownHosts || [];
            state.knownHosts.unshift({ id: `host-${Date.now()}`, host: p.host.host, port: p.host.port, fingerprint: p.fingerprint });
          } catch (e) {
            console.error("Failed to add known host", e);
          }
          connectHost(p.host, true);
          break;
        }
        case "save-connect": {
          readEditor();
          const host = await saveEditor();
          if (host) connectHost(host);
          break;
        }
        case "save-group":
          await saveGroupDetails();
          break;
        case "save-key":
          saveKeyDetails();
          break;
        case "copy-key-field":
          await copyKeyField(element.dataset.field);
          break;
        case "import-key-file":
          document.querySelector("#keyFileInput")?.click();
          break;
      case "delete-current": {
        const id = state.editingHost.id;
        await deleteHost(id);
        break;
      }
        case "auth-key":
          if (state.editingHost) {
            readEditor();
            state.editingHost.auth = toKeyAuth(state.editingHost.auth);
            render();
          }
          break;
        case "auth-password":
          if (state.editingHost) {
            readEditor();
            state.editingHost.auth = { kind: "password", password: "" };
            render();
          }
          break;
        case "group-auth-key":
          if (state.editingGroup) {
            readGroupDetails();
            state.editingGroup.auth = toKeyAuth(state.editingGroup.auth);
            render();
          }
          break;
        case "group-auth-password":
          if (state.editingGroup) {
            readGroupDetails();
            state.editingGroup.auth = { kind: "password", password: "" };
            render();
          }
          break;
        case "generate-key":
          openGenerateKeyDetails();
          break;
        case "generate-key-type":
          readKeyGenerator();
          state.keyGenerator.keyType = element.dataset.keyType || "ed25519";
          render();
          break;
        case "generate-ecdsa-size":
          readKeyGenerator();
          state.keyGenerator.ecdsaSize = Number(element.dataset.size || 521);
          render();
          break;
        case "generate-rsa-size":
          readKeyGenerator();
          state.keyGenerator.rsaSize = Number(element.dataset.size || 4096);
          render();
          break;
        case "generate-key-save":
          await generateAndSaveKey();
          break;
        case "new-identity":
          closeMenus();
          setStatus(t("SSH identity support is planned for a later milestone."));
          break;
        case "certificate-info":
          setStatus(t("SSH certificate support is planned for a later milestone."));
          break;
        case "new-snippet":
          closeMenus();
          await createSnippet();
          break;
        case "toggle-snippet-menu":
          state.snippetMenuOpen = !state.snippetMenuOpen;
          render();
          break;
        case "show-all-snippets":
          state.openedPackageId = null;
          render();
          break;
        case "new-snippet-package":
          closeMenus();
          openPackageDetails();
          break;
        case "edit-package": {
          const pkg = packageById(element.dataset.packageId);
          if (pkg) openPackageDetails(pkg);
          break;
        }
        case "save-package":
          savePackageDetails();
          render();
          break;
        case "remove-editing-package":
          if (state.editingPackage) await removePackage(state.editingPackage.id);
          break;
        case "ctx-edit-package": {
          const pkg = packageById(state.contextMenu?.id);
          state.contextMenu = null;
          if (pkg) openPackageDetails(pkg);
          break;
        }
        case "ctx-remove-package": {
          const id = state.contextMenu?.id;
          state.contextMenu = null;
          if (id) await removePackage(id);
          break;
        }
        case "edit-snippet": {
          const snippet = state.snippets.find((s) => s.id === element.dataset.snippetId);
          if (snippet) openSnippetDetails(snippet);
          break;
        }
        case "save-snippet":
          saveSnippetDetails();
          break;
      case "remove-editing-snippet": {
        if (state.editingSnippet) {
          await removeSnippet(state.editingSnippet.id);
        }
        break;
      }
        case "ctx-edit-snippet": {
          const snippet = contextSnippet();
          state.contextMenu = null;
          if (snippet) openSnippetDetails(snippet);
          break;
        }
    case "ctx-remove-snippet": {
      const snippet = contextSnippet();
      state.contextMenu = null;
      if (snippet) await removeSnippet(snippet.id);
      break;
    }
        case "import-known-hosts":
          state.importingKnownHosts = true;
          render();
          try {
            const newHosts = await call("import_known_hosts");
            if (newHosts && newHosts.length) {
              const existingIds = new Set((state.knownHosts || []).map(h => h.id));
              state.knownHosts = [...[...newHosts].reverse(), ...(state.knownHosts || [])];
              await call("save_known_hosts", { hosts: state.knownHosts });
            }
          } catch (e) {
            console.error("Failed to import known hosts", e);
          } finally {
            state.importingKnownHosts = false;
            render();
          }
          break;
        case "ctx-convert-known-host": {
          const kh = contextKnownHost();
          state.contextMenu = null;
          if (kh) {
            const newHost = {
              ...emptyHost(),
              name: "",
              host: kh.host,
              port: kh.port,
              username: "",
              group: "",
              auth: { kind: "password", password: "" },
            };
            state.hosts.push(newHost);
            await call("save_hosts", { hosts: state.hosts });
            state.selectedHostId = newHost.id;
            state.section = "hosts";
            render();
          }
          break;
        }
    case "ctx-remove-known-host": {
      const kh = contextKnownHost();
      state.contextMenu = null;
      if (!kh) break;
      const confirmed = await requestDeleteConfirmation({
        title: t("Remove known host"),
        message: t("Are you sure you want to remove this known host?"),
        item: {
          type: "host",
          title: kh.host || t("Unknown host"),
          subtitle: kh.fingerprint || t("SSH port {0}", kh.port || 22),
        },
      });
      if (!confirmed) break;
      state.knownHosts = state.knownHosts.filter((host) => host.id !== kh.id);
      await call("save_known_hosts", { hosts: state.knownHosts });
      setStatus(t("Known host removed"));
      render();
      break;
    }

        case "show-shell-history":
          openShellHistory();
          break;
        case "history-save":
          state.shellHistorySavingIndex = Number(element.dataset.index);
          render();
          requestAnimationFrame(() => {
            const input = document.querySelector(`#historyLabel-${element.dataset.index}`);
            if (input) input.focus();
          });
          break;
        case "history-done":
          saveHistoryAsSnippet(Number(element.dataset.index));
          break;
        case "copy-snippet":
          await copySnippetCommand(element.dataset.hostId, Number(element.dataset.index));
          break;
        case "run-command":
          runTerminalCommand();
          break;
        case "clear-terminal":
          state.terminal = "";
          xterm?.clear();
          render({ terminalBottom: true, focusTerminal: true });
          if (state.sessionKind === "ssh" && state.activeHost && !state.shellHealthy) {
            reconnectShell("manual clear");
          }
          break;
        case "refresh-sftp":
          refreshSftp();
          break;
        case "bottom-files":
          state.bottomTab = "files";
          render();
          break;
        case "bottom-commands":
          state.bottomTab = "commands";
          render();
          break;
        case "sftp-up":
          refreshSftp(parentPath(state.remotePath));
          break;
        case "create-folder":
          sftpNewFolder();
          break;
        case "upload-file": {
          const file = state.watchedFiles.find((item) => item.remotePath === element.dataset.remotePath);
          if (file) uploadWatched(file);
          break;
        }
        case "discard-file": {
          const file = state.watchedFiles.find((item) => item.remotePath === element.dataset.remotePath);
          if (file) file.dirty = false;
          render();
          break;
        }
      }
    });
  });

  document.querySelectorAll(".host-card").forEach((card) => {
    card.addEventListener("click", () => {
      if (cardClickTimer) window.clearTimeout(cardClickTimer);
      cardClickTimer = window.setTimeout(() => {
        selectCard("host", card.dataset.hostId);
        state.contextMenu = null;
        cardClickTimer = null;
        render();
      }, 170);
    });
    card.addEventListener("dblclick", () => {
      if (cardClickTimer) window.clearTimeout(cardClickTimer);
      cardClickTimer = null;
      const host = state.hosts.find((item) => item.id === card.dataset.hostId);
      if (host) connectHost(host);
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("host", card.dataset.hostId);
      state.contextMenu = {
        kind: "host",
        id: card.dataset.hostId,
        x: event.clientX,
        y: event.clientY,
      };
      render();
    });
  });

  document.querySelectorAll(".group-card[data-group]").forEach((card) => {
    card.addEventListener("click", () => {
      if (cardClickTimer) window.clearTimeout(cardClickTimer);
      cardClickTimer = window.setTimeout(() => {
        selectCard("group", card.dataset.group);
        state.contextMenu = null;
        cardClickTimer = null;
        render();
      }, 170);
    });
    card.addEventListener("dblclick", () => {
      if (cardClickTimer) window.clearTimeout(cardClickTimer);
      cardClickTimer = null;
      openGroup(card.dataset.group);
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("group", card.dataset.group);
      state.contextMenu = {
        kind: "group",
        group: card.dataset.group,
        x: event.clientX,
        y: event.clientY,
      };
      render();
    });
  });

  document.querySelectorAll(".key-card[data-key-id]").forEach((card) => {
    card.addEventListener("click", () => {
      selectCard("key", card.dataset.keyId);
      state.contextMenu = null;
      render();
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("key", card.dataset.keyId);
      state.contextMenu = {
        kind: "key",
        id: card.dataset.keyId,
        x: event.clientX,
        y: event.clientY,
      };
      render();
    });
  });

  document.querySelectorAll(".identity-card[data-identity-id]").forEach((card) => {
    card.addEventListener("click", () => {
      selectCard("identity", card.dataset.identityId);
      state.contextMenu = null;
      render();
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("identity", card.dataset.identityId);
      state.contextMenu = {
        kind: "identity",
        id: card.dataset.identityId,
        x: event.clientX,
        y: event.clientY,
      };
      render();
    });
  });

  document.querySelectorAll(".snippet-card[data-snippet-id]").forEach((card) => {
    card.addEventListener("click", () => {
      selectCard("snippet", card.dataset.snippetId);
      state.contextMenu = null;
      render();
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("snippet", card.dataset.snippetId);
      state.contextMenu = {
        kind: "snippet",
        id: card.dataset.snippetId,
        x: event.clientX,
        y: event.clientY,
      };
      render();
    });
  });

  document.querySelectorAll(".package-card[data-package-id]").forEach((card) => {
    card.addEventListener("click", () => {
      selectCard("package", card.dataset.packageId);
      state.contextMenu = null;
      render();
    });
    card.addEventListener("dblclick", () => {
      if (!packageById(card.dataset.packageId)) return;
      state.openedPackageId = card.dataset.packageId;
      state.selectedPackageId = null;
      render();
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("package", card.dataset.packageId);
      state.contextMenu = { kind: "package", id: card.dataset.packageId, x: event.clientX, y: event.clientY };
      render();
    });
  });

  document.querySelectorAll(".known-host-card[data-known-host-id]").forEach((card) => {
    card.addEventListener("click", () => {
      selectCard("known_host", card.dataset.knownHostId);
      state.contextMenu = null;
      render();
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectCard("known_host", card.dataset.knownHostId);
      state.contextMenu = {
        kind: "known_host",
        id: card.dataset.knownHostId,
        x: event.clientX,
        y: event.clientY,
      };
      render();
    });
  });

  const keyFileInput = document.querySelector("#keyFileInput");
  if (keyFileInput) {
    keyFileInput.addEventListener("change", () => {
      importKeyFile(keyFileInput.files?.[0]);
      keyFileInput.value = "";
    });
  }

  const keyDropzone = document.querySelector(".key-dropzone");
  if (keyDropzone) {
    keyDropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      keyDropzone.classList.add("dragging");
    });
    keyDropzone.addEventListener("dragleave", () => {
      keyDropzone.classList.remove("dragging");
    });
    keyDropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      keyDropzone.classList.remove("dragging");
      importKeyFile(event.dataTransfer?.files?.[0]);
    });
  }

  document.querySelectorAll(".key-textarea").forEach((textarea) => {
    textarea.addEventListener("input", () => {
      const copyButton = textarea.parentElement?.querySelector(".copy-chip");
      copyButton?.classList.toggle("empty", !textarea.value.trim());
    });
  });

  document.querySelector("[data-delete-backdrop]")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) resolveDeleteConfirmation(false);
  });

  const main = document.querySelector(".main");
  if (main) {
    main.addEventListener("click", (event) => {
      if (state.contextMenu && !event.target.closest(".context-menu")) {
        state.contextMenu = null;
        render();
        return;
      }
      
      const isCard = event.target.closest(".host-card,.group-card,.key-card,.identity-card,.snippet-card,.package-card,.known-host-card");
      if (!isCard && !event.target.closest("button") && !event.target.closest(".dropdown-menu") && !event.target.closest(".context-menu") && !event.target.closest(".toolstrip")) {
        let changed = state.selectedHostId || state.selectedGroup || state.selectedKeyId || state.selectedIdentityId || state.selectedSnippetId || state.selectedPackageId || state.selectedKnownHostId;
        selectCard(null, null);
        if (changed && !state.detailOpen) render();
      }

      if (!state.detailOpen) return;
      const keepOpen = event.target.closest(
        "button,input,select,textarea,.details-panel,.host-card,.group-card,.key-card,.identity-card,.snippet-card,.package-card,.known-host-card,.key-dropzone,.breadcrumb,.dropdown-menu,.context-menu,.search-row,.toolstrip,.section-head",
      );
      if (!keepOpen) closeEditor();
    });
  }

  const search = document.querySelector("#hostSearch");
  if (search) {
    search.addEventListener("input", () => {
      state.search = search.value;
      render();
    });
  }

  const localSearch = document.querySelector("#localSearch");
  if (localSearch) {
    localSearch.addEventListener("input", () => {
      state.search = localSearch.value;
      render();
    });
  }

  const sftpFilter = document.querySelector("#sftpFilter");
  if (sftpFilter) {
    sftpFilter.addEventListener("input", () => {
      state.sftpFilter = sftpFilter.value;
      render();
    });
  }

  const groupUseCredentials = document.querySelector("#groupUseCredentials");
  if (groupUseCredentials) {
    groupUseCredentials.addEventListener("change", () => {
      readGroupDetails();
      state.editingGroup.useCredentials = groupUseCredentials.checked;
      render();
    });
  }

  const commandInput = document.querySelector("#commandInput");
  if (commandInput) {
    commandInput.addEventListener("input", () => {
      state.commandInput = commandInput.value;
    });
    commandInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") runTerminalCommand();
    });
  }

  const terminalPane = document.querySelector("#terminalPane");
  if (terminalPane) {
    terminalPane.addEventListener("click", () => {
      state.terminalFocused = true;
      xterm?.focus();
    });
  }
}

async function copySnippetCommand(hostId, index) {
  const host = state.hosts.find((item) => item.id === hostId);
  const snippet = host?.snippets?.[index];
  if (!snippet) return;
  try {
    await navigator.clipboard.writeText(snippet.command);
    setStatus(t("Copied {0}", snippet.name));
  } catch {
    setStatus(snippet.command);
  }
}

function readEditor() {
  if (!state.editingHost || !document.getElementById("editName")) return;
  const host = state.editingHost;
  host.name = value("editName");
  host.group = value("editGroup") || "Default";
  host.host = value("editHost");
  host.port = value("editPort") ? Number(value("editPort")) : "";
  host.defaultPath = value("editDefaultPath") || "/root";
  if (!host.identityId) {
    host.username = value("editUsername");
    if (isKeyAuth(host.auth)) {
      const keyId = value("editKeyId");
      const key = selectedKey(keyId);
      host.auth = {
        kind: "keyRef",
        keyId,
        label: key?.label || "",
        passphrase: value("editKeyPassphrase"),
      };
    } else {
      host.auth.password = value("editPassword");
    }
  }
}

function readGroupDetails() {
  if (!state.editingGroup || !document.getElementById("groupName")) return;
  const group = state.editingGroup;
  const label = value("groupName") || groupLabel(group.name) || "Default";
  const parent = value("groupParent");
  group.name = joinGroupPath(parent, label);
  group.port = Number(value("groupPort") || group.port || 22);
  group.username = value("groupUsername") || group.username || "root";
  group.useCredentials = Boolean(document.querySelector("#groupUseCredentials")?.checked);
  if (isKeyAuth(group.auth)) {
    const keyId = value("groupKeyId");
    const key = selectedKey(keyId);
    group.auth = {
      kind: "keyRef",
      keyId,
      label: key?.label || "",
      passphrase: value("groupKeyPassphrase"),
    };
  } else {
    group.auth.password = value("groupPassword");
  }
}

function value(id) {
  return document.querySelector(`#${id}`)?.value.trim() || "";
}

function terminalColumns() {
  if (xterm?.cols) return xterm.cols;
  const terminal = document.querySelector("#terminalPane");
  if (!terminal) return 120;
  const style = getComputedStyle(terminal);
  const paddingX = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight);
  const { width } = terminalCellSize(terminal);
  return Math.max(60, Math.floor((terminal.clientWidth - paddingX) / width));
}

function terminalRows() {
  if (xterm?.rows) return xterm.rows;
  const terminal = document.querySelector("#terminalPane");
  if (!terminal) return 36;
  const style = getComputedStyle(terminal);
  const paddingY = parseFloat(style.paddingTop) + parseFloat(style.paddingBottom);
  const { height } = terminalCellSize(terminal);
  return Math.max(20, Math.floor((terminal.clientHeight - paddingY) / height) - 1);
}

function terminalCellSize(terminal) {
  const style = getComputedStyle(terminal);
  const probe = document.createElement("span");
  probe.textContent = "MMMMMMMMMM";
  probe.style.position = "absolute";
  probe.style.visibility = "hidden";
  probe.style.whiteSpace = "pre";
  probe.style.fontFamily = style.fontFamily;
  probe.style.fontSize = style.fontSize;
  probe.style.fontWeight = style.fontWeight;
  probe.style.lineHeight = style.lineHeight;
  document.body.appendChild(probe);
  const rect = probe.getBoundingClientRect();
  probe.remove();
  return {
    width: Math.max(6, rect.width / 10 || 9),
    height: Math.max(12, rect.height || 22),
  };
}

function barRow(label, pct, text) {
  return `
    <div class="bar-row">
      <span>${label}</span>
      <div class="bar"><span style="width:${Math.max(0, Math.min(100, pct))}%"></span></div>
      <strong>${escapeHtml(text)}</strong>
    </div>
  `;
}

function percent(used, total) {
  return total ? (used * 100) / total : 0;
}

function humanBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes || 0);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(1)} ${units[unit]}`;
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days ? `${days} d ${hours} h` : `${hours} h`;
}

function formatTime(seconds) {
  if (!seconds) return "-";
  return new Date(seconds * 1000).toLocaleString(currentLocale());
}

function formatMode(mode) {
  if (mode === null || mode === undefined) return "-";
  return (mode & 0o7777).toString(8);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value);
}

init();
