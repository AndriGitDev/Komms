"use strict";

(() => {
  const DEFAULT_LOCALE = "en-US";
  const STORAGE_KEY = "komms.locale";
  const FSI = "\u2068";
  const PDI = "\u2069";
  const catalogs = globalThis.KOMMS_LOCALIZATION_CATALOGS;
  const sourceIds = globalThis.KOMMS_LOCALIZATION_SOURCE_IDS;
  const trackedText = [];
  const trackedAttributes = [];
  const knownTextNodes = new WeakSet();
  const knownAttributeElements = new WeakMap();

  function validCatalog(candidate) {
    return candidate
      && candidate.direction === "ltr"
      && candidate.messages
      && typeof candidate.messages === "object"
      && !Array.isArray(candidate.messages);
  }

  if (
    !catalogs
    || !validCatalog(catalogs[DEFAULT_LOCALE])
    || !sourceIds
    || typeof sourceIds !== "object"
  ) {
    throw new Error("default localization catalog is unavailable");
  }

  function systemLocale() {
    const preferences = Array.isArray(navigator.languages)
      ? navigator.languages
      : [navigator.language];
    return preferences.some((language) => /^is(?:-|$)/iu.test(language ?? ""))
      ? "is"
      : DEFAULT_LOCALE;
  }

  function localePreference() {
    const stored = localStorage.getItem(STORAGE_KEY);
    return ["system", DEFAULT_LOCALE, "is"].includes(stored) ? stored : "system";
  }

  function activeLocale() {
    const preference = localePreference();
    const selected = preference === "system" ? systemLocale() : preference;
    return validCatalog(catalogs[selected]) ? selected : DEFAULT_LOCALE;
  }

  function pluralForm(locale, count) {
    if (!Number.isSafeInteger(count)) throw new TypeError("plural count must be an integer");
    if (locale === "is") {
      return count % 10 === 1 && count % 100 !== 11 ? "one" : "other";
    }
    return count === 1 ? "one" : "other";
  }

  function templateFor(id, count = null) {
    const locale = activeLocale();
    const selected = catalogs[locale].messages[id]
      ?? catalogs[DEFAULT_LOCALE].messages[id];
    if (selected === undefined) throw new RangeError(`unknown localization id: ${id}`);
    if (typeof selected === "string") {
      if (count !== null) throw new TypeError(`${id} is not plural`);
      return { locale, template: selected };
    }
    if (!selected || typeof selected !== "object" || count === null) {
      throw new TypeError(`${id} requires a plural count`);
    }
    return { locale, template: selected[pluralForm(locale, count)] ?? selected.other };
  }

  function format(template, args) {
    let implicitPosition = 0;
    return template.replace(/%(?:([1-9][0-9]*)\$)?([sd%])/gu, (_, explicit, kind) => {
      if (kind === "%") return "%";
      const position = explicit ? Number(explicit) - 1 : implicitPosition++;
      if (position < 0 || position >= args.length) {
        throw new RangeError(`missing localization argument ${position + 1}`);
      }
      const value = args[position];
      if (kind === "d") {
        if (!Number.isSafeInteger(value)) {
          throw new TypeError(`localization argument ${position + 1} must be an integer`);
        }
        return new Intl.NumberFormat(activeLocale()).format(value);
      }
      return `${FSI}${String(value)}${PDI}`;
    });
  }

  function l10n(id, ...args) {
    const { template } = templateFor(id);
    return format(template, args);
  }

  function l10nPlural(id, count, ...args) {
    const { template } = templateFor(id, count);
    return format(template, args.length === 0 ? [count] : args);
  }

  function l10nSource(source) {
    const id = sourceIds[source];
    return id ? l10n(id) : source;
  }

  function localizeAttribute(element, attribute, id) {
    if (id) element.setAttribute(attribute, l10n(id));
  }

  function sourceText(value) {
    return value.trim().replace(/\s+/gu, " ");
  }

  function trackSourceText(scope) {
    const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const parent = node.parentElement;
      if (
        knownTextNodes.has(node)
        || !parent
        || parent.closest("script, style, svg, [data-l10n]")
      ) {
        continue;
      }
      const source = sourceText(node.nodeValue ?? "");
      const id = sourceIds[source];
      if (!id) continue;
      const raw = node.nodeValue ?? "";
      const prefix = raw.match(/^\s*/u)?.[0] ?? "";
      const suffix = raw.match(/\s*$/u)?.[0] ?? "";
      knownTextNodes.add(node);
      trackedText.push({ node, id, prefix, suffix });
    }
  }

  function trackSourceAttributes(scope) {
    const attributes = ["aria-label", "placeholder", "title"];
    const elements = scope.querySelectorAll("*");
    for (const element of elements) {
      if (element.closest("[data-l10n]")) continue;
      let known = knownAttributeElements.get(element);
      if (!known) {
        known = new Set();
        knownAttributeElements.set(element, known);
      }
      for (const attribute of attributes) {
        if (known.has(attribute)) continue;
        const source = sourceText(element.getAttribute(attribute) ?? "");
        const id = sourceIds[source];
        if (!id) continue;
        known.add(attribute);
        trackedAttributes.push({ element, attribute, id });
      }
    }
  }

  function trackSourceRoot(scope) {
    trackSourceText(scope);
    trackSourceAttributes(scope);
  }

  function localizeTrackedSource() {
    for (const item of trackedText) {
      if (item.node.isConnected || item.node.getRootNode() instanceof DocumentFragment) {
        item.node.nodeValue = `${item.prefix}${l10n(item.id)}${item.suffix}`;
      }
    }
    for (const item of trackedAttributes) {
      if (
        item.element.isConnected
        || item.element.getRootNode() instanceof DocumentFragment
      ) {
        item.element.setAttribute(item.attribute, l10n(item.id));
      }
    }
  }

  function localizeRoot(root = document, trackSource = false) {
    const visit = (scope) => {
      for (const element of scope.querySelectorAll("[data-l10n]")) {
        element.textContent = l10n(element.dataset.l10n);
      }
      for (const element of scope.querySelectorAll("[data-l10n-placeholder]")) {
        localizeAttribute(element, "placeholder", element.dataset.l10nPlaceholder);
      }
      for (const element of scope.querySelectorAll("[data-l10n-aria-label]")) {
        localizeAttribute(element, "aria-label", element.dataset.l10nAriaLabel);
      }
      for (const element of scope.querySelectorAll("[data-l10n-title]")) {
        localizeAttribute(element, "title", element.dataset.l10nTitle);
      }
    };
    visit(root);
    if (trackSource) trackSourceRoot(root);
    for (const template of root.querySelectorAll("template")) {
      visit(template.content);
      if (trackSource) trackSourceRoot(template.content);
    }
    localizeTrackedSource();
    document.documentElement.lang = activeLocale();
  }

  function setLocale(preference) {
    if (!["system", DEFAULT_LOCALE, "is"].includes(preference)) {
      throw new RangeError("unsupported locale preference");
    }
    localStorage.setItem(STORAGE_KEY, preference);
    localizeRoot();
    document.dispatchEvent(new CustomEvent("kommslocalechange", {
      detail: { locale: activeLocale(), preference },
    }));
  }

  function localizedError(error) {
    const reason = String(error ?? "").toLocaleLowerCase("en-US");
    if (reason.startsWith("startup") || reason.includes("could not start")) {
      return l10n("error_startup");
    }
    if (reason.includes("locked") || reason.includes("stopped")) {
      return l10n("error_node_stopped");
    }
    if (reason.includes("folder")) return l10n("error_folder");
    if (reason.includes("label")) return l10n("error_label");
    if (reason.includes("pin")) return l10n("error_pin");
    if (reason.includes("setting")) return l10n("error_settings");
    if (
      reason.includes("invalid")
      || reason.includes("must ")
      || reason.includes("required")
      || reason.includes("empty")
    ) {
      return l10n("error_input");
    }
    return l10n("error_generic");
  }

  Object.assign(globalThis, {
    l10n,
    l10nPlural,
    l10nSource,
    localizedError,
    KommsLocalization: Object.freeze({
      activeLocale,
      localePreference,
      localizeRoot,
      setLocale,
    }),
  });

  localizeRoot(document, true);
})();
