(() => {
  // =========================
  // Antigravity Config Lab v2
  // 约束：Tailwind + 禁止 inline style（style="" / el.style=...）
  // =========================

  // DOM helpers
  const $ = (id) => document.getElementById(id);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  // -------------------------
  // UI helpers
  // -------------------------
  const ui = {
    toast: (message, type = "info") => {
      const container = $("toastContainer");
      if (!container) {
        try {
          alert(String(message));
        } catch (_) {}
        return;
      }

      const el = document.createElement("div");
      el.className = `toast ${type}`;

      // 时间戳：终端日志风格（24h）
      const time = new Date().toLocaleTimeString("zh-CN", { hour12: false });

      const text = document.createElement("span");
      text.className = "toast-text";
      text.textContent = `[${time}] ${String(message)}`;

      const close = document.createElement("button");
      close.type = "button";
      close.className = "toast-close ag-btn ag-btn-ghost";
      close.textContent = "关闭";
      close.addEventListener("click", () => el.remove());

      el.appendChild(text);
      el.appendChild(close);
      container.appendChild(el);

      setTimeout(() => {
        el.classList.add("toast-fadeout");
        el.addEventListener("animationend", () => el.remove(), { once: true });
        setTimeout(() => el.remove(), 600);
      }, 4000);
    },

    // 为按钮显示 loading（复用 glitch-active 动画）
    setLoading: (btn, isLoading, text = "") => {
      if (!btn) return;
      if (isLoading) {
        if (!btn.dataset.originalHtml) btn.dataset.originalHtml = btn.innerHTML;
        btn.disabled = true;
        const label = (text || "处理中…").trim();
        btn.innerHTML = `<span>[ ${label} ]</span>`;
        btn.classList.add("glitch-active");
      } else {
        btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
        btn.disabled = false;
        btn.classList.remove("glitch-active");
      }
    },

    renderSkeletonList: (count = 6) => {
      return Array(count)
        .fill(0)
        .map(
          () => `
        <li class="rule-item skeleton-list-item">
          <div class="skeleton skeleton-text w-2/5"></div>
          <div class="skeleton skeleton-text w-1/5"></div>
        </li>
      `
        )
        .join("");
    },

    tag: (text, variant = "muted") => {
      const el = document.createElement("span");
      const base =
        "inline-flex items-center rounded border px-2 py-0.5 text-[10px] tracking-widest uppercase";
      const styles = {
        muted: "border-ag-border text-ag-muted",
        ok: "border-ag-primary text-ag-primary",
        info: "border-ag-secondary text-ag-secondary",
        warn: "border-ag-warning text-ag-warning",
        danger: "border-ag-danger text-ag-danger",
      };
      el.className = `${base} ${styles[variant] || styles.muted}`;
      el.textContent = text;
      return el;
    },

    confirmDanger: async (title, detail) => {
      const ok1 = confirm(`${title}\n\n${detail}\n\n确认继续？`);
      if (!ok1) return false;
      const ok2 = confirm("请再次确认：真的要继续吗？");
      return ok2;
    },
  };

  // -------------------------
  // Utils
  // -------------------------
  const deepClone = (x) => JSON.parse(JSON.stringify(x ?? {}));
  const isPlainObject = (v) => !!v && typeof v === "object" && !Array.isArray(v);
  const ensureObjIn = (parent, key) => {
    if (!isPlainObject(parent)) return {};
    if (!isPlainObject(parent[key])) parent[key] = {};
    return parent[key];
  };

  const debounce = (fn, waitMs = 400) => {
    let t = 0;
    return (...args) => {
      if (t) window.clearTimeout(t);
      t = window.setTimeout(() => fn(...args), waitMs);
    };
  };

  const toLower = (s) => String(s ?? "").toLowerCase();
  const trim = (s) => String(s ?? "").trim();

  const normalizeEnum = (value, allowed, fallback) => {
    const v = toLower(value);
    if (allowed.includes(v)) return v;
    return fallback;
  };

  const normalizeBool = (value, fallback) => {
    if (typeof value === "boolean") return value;
    return !!fallback;
  };

  const normalizeInt = (value, fallback) => {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.trunc(n);
  };

  const normalizeStringArray = (value) => {
    if (!Array.isArray(value)) return [];
    return value.map((x) => String(x)).map((x) => x.trim()).filter(Boolean);
  };

  const normalizePortArray = (value) => {
    // 对齐后端：过滤非法端口（1~65535），排序去重；空数组=全部
    if (!Array.isArray(value)) return [];
    const out = [];
    for (const item of value) {
      const n = normalizeInt(item, NaN);
      if (!Number.isFinite(n) || n <= 0 || n > 65535) continue;
      out.push(n);
    }
    out.sort((a, b) => a - b);
    return out.filter((v, i) => i === 0 || v !== out[i - 1]);
  };

  // -------------------------
  // Default config (matches Config.hpp defaults)
  // -------------------------
  const defaultConfig = () => ({
    log_level: "info",
    proxy: { host: "127.0.0.1", port: 7890, type: "socks5" },
    fake_ip: { enabled: true, cidr: "198.18.0.0/15" },
    timeout: { connect: 5000, send: 5000, recv: 5000 },
    proxy_rules: {
      allowed_ports: [80, 443],
      dns_mode: "direct",
      ipv6_mode: "proxy",
      udp_mode: "block",
      routing: {
        enabled: true,
        priority_mode: "order",
        default_action: "proxy",
        use_default_private: true,
        rules: [],
      },
    },
    traffic_logging: false,
    child_injection: true,
    child_injection_mode: "filtered",
    child_injection_exclude: [],
    target_processes: [],
  });

  const defaultRoutingRule = () => ({
    name: "new-rule",
    enabled: true,
    action: "proxy",
    priority: 0,
    ip_cidrs_v4: [],
    ip_cidrs_v6: [],
    domains: [],
    ports: [],
    protocols: ["tcp"],
  });

  const normalizeConfig = (raw) => {
    const base = defaultConfig();
    const j = raw && typeof raw === "object" ? raw : {};

    const out = deepClone(base);

    // log_level
    out.log_level = normalizeEnum(j.log_level, ["debug", "info", "warn", "error"], base.log_level);

    // proxy
    const p = j.proxy && typeof j.proxy === "object" ? j.proxy : {};
    out.proxy.host = trim(typeof p.host === "string" ? p.host : base.proxy.host) || base.proxy.host;
    out.proxy.type = normalizeEnum(p.type, ["socks5", "http"], base.proxy.type);
    {
      const port = normalizeInt(p.port, base.proxy.port);
      // 对齐后端：允许 0（禁用代理）；<0 或 >65535 回退 7890
      out.proxy.port = port < 0 || port > 65535 ? base.proxy.port : port;
    }

    // fake_ip
    const fip = j.fake_ip && typeof j.fake_ip === "object" ? j.fake_ip : {};
    out.fake_ip.enabled = normalizeBool(fip.enabled, base.fake_ip.enabled);
    out.fake_ip.cidr = trim(typeof fip.cidr === "string" ? fip.cidr : base.fake_ip.cidr) || base.fake_ip.cidr;

    // timeout
    const t = j.timeout && typeof j.timeout === "object" ? j.timeout : {};
    out.timeout.connect = Math.max(1, normalizeInt(t.connect, base.timeout.connect));
    out.timeout.send = Math.max(1, normalizeInt(t.send, base.timeout.send));
    out.timeout.recv = Math.max(1, normalizeInt(t.recv, base.timeout.recv));

    // proxy_rules
    const pr = j.proxy_rules && typeof j.proxy_rules === "object" ? j.proxy_rules : {};
    out.proxy_rules.allowed_ports = normalizePortArray(pr.allowed_ports ?? base.proxy_rules.allowed_ports);
    out.proxy_rules.dns_mode = normalizeEnum(pr.dns_mode, ["direct", "proxy"], base.proxy_rules.dns_mode);
    out.proxy_rules.ipv6_mode = normalizeEnum(pr.ipv6_mode, ["proxy", "direct", "block"], base.proxy_rules.ipv6_mode);
    out.proxy_rules.udp_mode = normalizeEnum(pr.udp_mode, ["block", "direct"], base.proxy_rules.udp_mode);

    // routing
    const rt = pr.routing && typeof pr.routing === "object" ? pr.routing : {};
    out.proxy_rules.routing.enabled = normalizeBool(rt.enabled, base.proxy_rules.routing.enabled);
    out.proxy_rules.routing.use_default_private = normalizeBool(
      rt.use_default_private,
      base.proxy_rules.routing.use_default_private
    );
    out.proxy_rules.routing.priority_mode = normalizeEnum(rt.priority_mode, ["order", "number"], base.proxy_rules.routing.priority_mode);
    out.proxy_rules.routing.default_action = normalizeEnum(rt.default_action, ["proxy", "direct"], base.proxy_rules.routing.default_action);

    const rulesIn = Array.isArray(rt.rules) ? rt.rules : base.proxy_rules.routing.rules;
    out.proxy_rules.routing.rules = rulesIn.map((r, idx) => {
      const rule = { ...defaultRoutingRule(), ...(r && typeof r === "object" ? r : {}) };
      rule.name = trim(rule.name) || `rule-${idx + 1}`;
      rule.enabled = normalizeBool(rule.enabled, true);
      rule.action = normalizeEnum(rule.action, ["proxy", "direct"], out.proxy_rules.routing.default_action);
      rule.priority = normalizeInt(rule.priority, 0);
      rule.ip_cidrs_v4 = normalizeStringArray(rule.ip_cidrs_v4);
      rule.ip_cidrs_v6 = normalizeStringArray(rule.ip_cidrs_v6);
      rule.domains = normalizeStringArray(rule.domains);
      rule.ports = normalizeStringArray(rule.ports);
      rule.protocols = normalizeStringArray(rule.protocols);
      if (rule.protocols.length === 0) rule.protocols = ["tcp"];
      return rule;
    });

    // Phase2/3
    out.traffic_logging = normalizeBool(j.traffic_logging, base.traffic_logging);
    out.child_injection = normalizeBool(j.child_injection, base.child_injection);
    out.child_injection_mode = normalizeEnum(j.child_injection_mode, ["filtered", "inherit"], base.child_injection_mode);
    out.child_injection_exclude = normalizeStringArray(j.child_injection_exclude);
    out.target_processes = normalizeStringArray(j.target_processes);

    return out;
  };

  // -------------------------
  // Routing engine (ported from src/core/Config.hpp)
  // -------------------------
  const routingEngine = (() => {
    const endsWith = (s, suffix) => s.length >= suffix.length && s.slice(s.length - suffix.length) === suffix;

    const parseIPv4 = (ip) => {
      const s = trim(ip);
      const parts = s.split(".");
      if (parts.length !== 4) return null;
      let out = 0;
      for (const p of parts) {
        if (!/^\d{1,3}$/.test(p)) return null;
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
        out = (out << 8) | n;
      }
      return out >>> 0;
    };

    const parseIPv6 = (ip) => {
      const s0 = trim(ip);
      if (!s0) return null;
      const s = s0.toLowerCase();
      if ((s.match(/::/g) || []).length > 1) return null;

      const parseHexWord = (part) => {
        const t = trim(part);
        if (!t || t.length > 4) return null;
        if (!/^[0-9a-f]+$/i.test(t)) return null;
        const v = parseInt(t, 16);
        if (!Number.isFinite(v) || v < 0 || v > 0xffff) return null;
        return v;
      };

      const parseSide = (side) => {
        if (!side) return [];
        const tokens = side.split(":");
        const words = [];
        for (let i = 0; i < tokens.length; i++) {
          const tok = tokens[i];
          if (tok === "") return null;
          if (tok.includes(".")) {
            // IPv4-embedded: only allowed at the end
            if (i !== tokens.length - 1) return null;
            const ip4 = parseIPv4(tok);
            if (ip4 === null) return null;
            words.push((ip4 >>> 16) & 0xffff);
            words.push(ip4 & 0xffff);
            continue;
          }
          const w = parseHexWord(tok);
          if (w === null) return null;
          words.push(w);
        }
        return words;
      };

      let words = [];
      if (s.includes("::")) {
        const [left, right] = s.split("::");
        const wl = parseSide(left);
        const wr = parseSide(right);
        if (!wl || !wr) return null;
        if (wl.length + wr.length > 8) return null;
        const fill = 8 - (wl.length + wr.length);
        if (fill <= 0) return null; // :: must compress at least one group
        words = [...wl, ...Array(fill).fill(0), ...wr];
      } else {
        const w = parseSide(s);
        if (!w || w.length !== 8) return null;
        words = w;
      }
      if (words.length !== 8) return null;

      const bytes = new Uint8Array(16);
      for (let i = 0; i < 8; i++) {
        bytes[i * 2] = (words[i] >> 8) & 0xff;
        bytes[i * 2 + 1] = words[i] & 0xff;
      }
      return bytes;
    };

    const parseCidrV4 = (cidr) => {
      const s = trim(cidr);
      const slash = s.indexOf("/");
      if (slash === -1) return null;
      const ipPart = trim(s.slice(0, slash));
      const bitsPart = trim(s.slice(slash + 1));
      if (!/^\d+$/.test(bitsPart)) return null;
      const bits = Number(bitsPart);
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
      const ip = parseIPv4(ipPart);
      if (ip === null) return null;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return { network: (ip & mask) >>> 0, mask };
    };

    const parseCidrV6 = (cidr) => {
      const s = trim(cidr);
      const slash = s.indexOf("/");
      if (slash === -1) return null;
      const ipPart = trim(s.slice(0, slash));
      const bitsPart = trim(s.slice(slash + 1));
      if (!/^\d+$/.test(bitsPart)) return null;
      const bits = Number(bitsPart);
      if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
      const addr = parseIPv6(ipPart);
      if (!addr) return null;

      const network = new Uint8Array(addr);
      if (bits === 0) {
        network.fill(0);
      } else if (bits < 128) {
        const fullBytes = Math.floor(bits / 8);
        const rem = bits % 8;
        if (fullBytes < 16) {
          const mask = rem === 0 ? 0 : (0xff << (8 - rem)) & 0xff;
          network[fullBytes] = network[fullBytes] & mask;
          for (let i = fullBytes + 1; i < 16; i++) network[i] = 0;
        }
      }
      return { network, prefix: bits };
    };

    const matchCidrV4 = (ip, rule) => (((ip & rule.mask) >>> 0) === rule.network);

    const matchCidrV6 = (ipBytes, rule) => {
      const bits = rule.prefix;
      const fullBytes = Math.floor(bits / 8);
      const rem = bits % 8;
      for (let i = 0; i < fullBytes; i++) {
        if (ipBytes[i] !== rule.network[i]) return false;
      }
      if (rem === 0) return true;
      const mask = (0xff << (8 - rem)) & 0xff;
      return (ipBytes[fullBytes] & mask) === (rule.network[fullBytes] & mask);
    };

    const globMatch = (pattern, text) => {
      let p = 0;
      let t = 0;
      let star = -1;
      let match = 0;
      while (t < text.length) {
        if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
          p++;
          t++;
        } else if (p < pattern.length && pattern[p] === "*") {
          star = p++;
          match = t;
        } else if (star !== -1) {
          p = star + 1;
          t = ++match;
        } else {
          return false;
        }
      }
      while (p < pattern.length && pattern[p] === "*") p++;
      return p === pattern.length;
    };

    const matchDomainPattern = (pattern, hostLower) => {
      if (!pattern || !hostLower) return false;
      const p = pattern;
      const h = hostLower;
      const hasWildcard = p.includes("*") || p.includes("?");
      if (!hasWildcard && p[0] === ".") {
        const root = p.slice(1);
        if (h.length === root.length && h === root) return true;
        return endsWith(h, p);
      }
      if (!hasWildcard) return h === p;
      return globMatch(p, h);
    };

    const parsePortRange = (token) => {
      const t = String(token ?? "").replace(/\s+/g, "");
      if (!t) return null;
      const dash = t.indexOf("-");
      if (dash === -1) {
        if (!/^\d+$/.test(t)) return null;
        const v = Number(t);
        if (!Number.isInteger(v) || v < 0 || v > 65535) return null;
        return { start: v, end: v };
      }
      const a = t.slice(0, dash);
      const b = t.slice(dash + 1);
      if (!a || !b) return null;
      if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) return null;
      let va = Number(a);
      let vb = Number(b);
      if (!Number.isInteger(va) || !Number.isInteger(vb)) return null;
      if (va < 0 || vb < 0 || va > 65535 || vb > 65535) return null;
      if (va > vb) [va, vb] = [vb, va];
      return { start: va, end: vb };
    };

    const matchPort = (port, ranges) => {
      if (!ranges.length) return true;
      if (!port) return false; // port==0 => false
      for (const r of ranges) {
        if (port >= r.start && port <= r.end) return true;
      }
      return false;
    };

    const matchProtocol = (protocol, protocolsLower) => {
      if (!protocolsLower.length) return true;
      const p = toLower(protocol);
      return protocolsLower.includes(p);
    };

    const compileRouting = (routing) => {
      const stats = {
        valid_cidr_v4: 0,
        valid_cidr_v6: 0,
        valid_port_ranges: 0,
        skipped_invalid_items: 0,
        skipped_invalid_cidr_v4: 0,
        skipped_invalid_cidr_v6: 0,
        skipped_invalid_ports: 0,
      };

      const compiled = [];
      const order = [];

      const srcRules = Array.isArray(routing?.rules) ? routing.rules.slice() : [];
      if (routing?.use_default_private) {
        srcRules.unshift({
          name: "default-private",
          enabled: true,
          action: "direct",
          priority: 0,
          ip_cidrs_v4: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
          ip_cidrs_v6: ["fc00::/7", "fe80::/10", "::1/128"],
          domains: [],
          ports: [],
          protocols: ["tcp"],
        });
      }

      const defaultAction = normalizeEnum(routing?.default_action, ["proxy", "direct"], "proxy");

      for (const r0 of srcRules) {
        const raw = { ...defaultRoutingRule(), ...(r0 && typeof r0 === "object" ? r0 : {}) };
        raw.name = trim(raw.name) || "(unnamed)";
        raw.enabled = normalizeBool(raw.enabled, true);
        raw.action = toLower(raw.action);
        if (raw.action !== "proxy" && raw.action !== "direct") {
          raw.action = defaultAction;
        }

        const cr = {
          raw,
          v4: [],
          v6: [],
          domains: [],
          port_ranges: [],
          protocols: [],
        };

        // CIDR v4
        for (const cidr of normalizeStringArray(raw.ip_cidrs_v4)) {
          const parsed = parseCidrV4(cidr);
          if (parsed) {
            cr.v4.push(parsed);
            stats.valid_cidr_v4++;
          } else {
            stats.skipped_invalid_items++;
            stats.skipped_invalid_cidr_v4++;
          }
        }

        // CIDR v6
        for (const cidr of normalizeStringArray(raw.ip_cidrs_v6)) {
          const parsed = parseCidrV6(cidr);
          if (parsed) {
            cr.v6.push(parsed);
            stats.valid_cidr_v6++;
          } else {
            stats.skipped_invalid_items++;
            stats.skipped_invalid_cidr_v6++;
          }
        }

        // domains
        for (const d of normalizeStringArray(raw.domains)) {
          const norm = toLower(d);
          if (norm) cr.domains.push(norm);
        }

        // ports
        for (const p of normalizeStringArray(raw.ports)) {
          const pr = parsePortRange(p);
          if (pr) {
            cr.port_ranges.push(pr);
            stats.valid_port_ranges++;
          } else {
            stats.skipped_invalid_items++;
            stats.skipped_invalid_ports++;
          }
        }

        // protocols
        for (const proto of normalizeStringArray(raw.protocols)) {
          const norm = toLower(proto);
          if (norm) cr.protocols.push(norm);
        }

        compiled.push(cr);
      }

      for (let i = 0; i < compiled.length; i++) order.push(i);
      const useNumber = toLower(routing?.priority_mode) === "number";
      if (useNumber) {
        // stable sort by priority desc
        order.sort((a, b) => (compiled[b].raw.priority || 0) - (compiled[a].raw.priority || 0));
      }

      return { compiled, order, defaultAction, stats, enabled: !!routing?.enabled };
    };

    const matchRouting = (compiledState, host, ip, ipIsV6, port, protocol) => {
      if (!compiledState?.enabled) return { matched: false, action: "", rule: "" };

      const defaultAction = compiledState.defaultAction || "proxy";

      let hostStr = trim(host);
      if (hostStr.endsWith(".")) hostStr = hostStr.slice(0, -1);
      hostStr = hostStr ? toLower(hostStr) : "";

      const hasHost = !!hostStr;
      const hasIp = !!trim(ip);

      let ip4Valid = false;
      let ip6Valid = false;
      let ip4 = 0;
      let ip6 = null;

      if (hasIp) {
        if (ipIsV6) {
          ip6 = parseIPv6(ip);
          ip6Valid = !!ip6;
        } else {
          const v = parseIPv4(ip);
          ip4Valid = v !== null;
          ip4 = v ?? 0;
        }
      } else if (hasHost) {
        const v4 = parseIPv4(hostStr);
        if (v4 !== null) {
          ip4Valid = true;
          ip4 = v4;
        } else {
          const v6 = parseIPv6(hostStr);
          if (v6) {
            ip6Valid = true;
            ip6 = v6;
          }
        }
      }

      for (const idx of compiledState.order) {
        const rule = compiledState.compiled[idx];
        if (!rule.raw.enabled) continue;
        if (!matchProtocol(protocol, rule.protocols)) continue;
        if (!matchPort(port, rule.port_ranges)) continue;

        let matched = false;
        if (hasHost && rule.domains.length) {
          for (const p of rule.domains) {
            if (matchDomainPattern(p, hostStr)) {
              matched = true;
              break;
            }
          }
        }

        if (!matched && ip4Valid && rule.v4.length) {
          for (const r of rule.v4) {
            if (matchCidrV4(ip4, r)) {
              matched = true;
              break;
            }
          }
        }

        if (!matched && ip6Valid && rule.v6.length && ip6) {
          for (const r of rule.v6) {
            if (matchCidrV6(ip6, r)) {
              matched = true;
              break;
            }
          }
        }

        if (matched) {
          return { matched: true, action: rule.raw.action || defaultAction, rule: rule.raw.name || "(unnamed)" };
        }
      }

      // 对齐后端：未命中时 action=default_action，rule=""，matched=false
      return { matched: false, action: defaultAction, rule: "" };
    };

    return {
      compileRouting,
      matchRouting,
      parseCidrV4,
      parseCidrV6,
    };
  })();

  // -------------------------
  // Validation
  // -------------------------
  const validateDraft = (cfg) => {
    const errors = {};
    const add = (key, msg) => {
      errors[key] = msg;
    };

    // log_level
    if (!["debug", "info", "warn", "error"].includes(toLower(cfg.log_level))) {
      add("logLevel", "log_level 必须是 debug/info/warn/error");
    }

    // proxy
    if (!["socks5", "http"].includes(toLower(cfg.proxy.type))) {
      add("proxyType", "proxy.type 必须是 socks5/http");
    }
    if (cfg.proxy.port < 0 || cfg.proxy.port > 65535) {
      add("proxyPort", "proxy.port 允许范围：0~65535（0=禁用）");
    }
    if (cfg.proxy.port !== 0 && !trim(cfg.proxy.host)) {
      add("proxyHost", "启用代理时 proxy.host 不能为空");
    }

    // fake_ip
    if (cfg.fake_ip.enabled) {
      // 后端 FakeIP 仅解析 IPv4 CIDR（见 FakeIP.hpp ParseCidr）
      if (!routingEngine.parseCidrV4(cfg.fake_ip.cidr)) {
        add("fakeIpCidr", "fake_ip.cidr 需为有效 IPv4 CIDR（示例：198.18.0.0/15）");
      }
    }

    // timeout (>0)
    if (!(cfg.timeout.connect > 0)) add("timeoutConnect", "timeout.connect 必须 > 0");
    if (!(cfg.timeout.send > 0)) add("timeoutSend", "timeout.send 必须 > 0");
    if (!(cfg.timeout.recv > 0)) add("timeoutRecv", "timeout.recv 必须 > 0");

    // proxy_rules enums
    if (!["direct", "proxy"].includes(toLower(cfg.proxy_rules.dns_mode))) add("dnsMode", "dns_mode 必须 direct/proxy");
    if (!["proxy", "direct", "block"].includes(toLower(cfg.proxy_rules.ipv6_mode)))
      add("ipv6Mode", "ipv6_mode 必须 proxy/direct/block");
    if (!["block", "direct"].includes(toLower(cfg.proxy_rules.udp_mode))) add("udpMode", "udp_mode 必须 block/direct");

    // allowed_ports
    for (const p of cfg.proxy_rules.allowed_ports) {
      if (!Number.isInteger(p) || p <= 0 || p > 65535) {
        add("allowedPorts", "allowed_ports 必须为 1~65535 的整数数组（空=全部）");
        break;
      }
    }

    // routing enums
    const rt = cfg.proxy_rules.routing;
    if (!["order", "number"].includes(toLower(rt.priority_mode))) add("priorityMode", "priority_mode 必须 order/number");
    if (!["proxy", "direct"].includes(toLower(rt.default_action))) add("defaultAction", "default_action 必须 proxy/direct");

    // child injection enums
    if (!["filtered", "inherit"].includes(toLower(cfg.child_injection_mode))) {
      add("childInjectionMode", "child_injection_mode 必须 filtered/inherit");
    }

    return { ok: Object.keys(errors).length === 0, errors };
  };

  // -------------------------
  // State
  // -------------------------
  const state = {
    baseRaw: {},
    loadedName: "",
    draft: defaultConfig(),
    dirty: false,
    currentSection: "overview",
    selectedRuleIndex: 0,
    isRuleListLoading: false,
    compiledRouting: routingEngine.compileRouting(defaultConfig().proxy_rules.routing),
    probe: { loading: false, results: [] },
  };

  const markDirty = () => {
    if (state.dirty) return;
    state.dirty = true;
    renderDirtyBadge();
  };

  // -------------------------
  // Elements
  // -------------------------
  const el = {
    // navigation
    sideNav: $("sideNav"),
    panels: $$("[data-section-panel]"),
    dirtyBadge: $("dirtyBadge"),
    configStatus: $("configStatus"),
    configSummary: $("configSummary"),
    runtimeBehaviorHint: $("runtimeBehaviorHint"),

    // file ops
    configFile: $("configFile"),
    btnDownload: $("btnDownload"),
    btnLoadExample: $("btnLoadExample"),

    // overview onboarding
    onboardingCard: $("onboardingCard"),
    btnOnboardingHide: $("btnOnboardingHide"),
    btnOnboardingNever: $("btnOnboardingNever"),

    // preset templates
    presetButtons: $$(".template-btn"),

    // proxy
    proxyEnabled: $("proxyEnabled"),
    proxyType: $("proxyType"),
    proxyHost: $("proxyHost"),
    proxyPort: $("proxyPort"),
    proxyDetectBadge: $("proxyDetectBadge"),
    btnProbePorts: $("btnProbePorts"),
    proxyProbeList: $("proxyProbeList"),

    // logging
    logLevel: $("logLevel"),
    trafficLogging: $("trafficLogging"),

    // network policy
    fakeIpEnabled: $("fakeIpEnabled"),
    fakeIpCidr: $("fakeIpCidr"),
    timeoutConnect: $("timeoutConnect"),
    timeoutSend: $("timeoutSend"),
    timeoutRecv: $("timeoutRecv"),
    dnsMode: $("dnsMode"),
    ipv6Mode: $("ipv6Mode"),
    udpMode: $("udpMode"),
    allowedPortsList: $("allowedPortsList"),
    btnAllowedPortsAdd: $("btnAllowedPortsAdd"),
    btnAllowedPortsClear: $("btnAllowedPortsClear"),

    // routing global
    routingEnabled: $("routingEnabled"),
    useDefaultPrivate: $("useDefaultPrivate"),
    priorityMode: $("priorityMode"),
    defaultAction: $("defaultAction"),
    priorityWarning: $("priorityWarning"),

    // routing rules
    ruleList: $("ruleList"),
    btnAddRule: $("btnAddRule"),
    btnCloneRule: $("btnCloneRule"),
    btnMoveUp: $("btnMoveUp"),
    btnMoveDown: $("btnMoveDown"),
    btnDeleteRule: $("btnDeleteRule"),

    ruleEditorForm: $("ruleEditorForm"),
    ruleName: $("ruleName"),
    ruleAction: $("ruleAction"),
    rulePriority: $("rulePriority"),
    ruleEnabled: $("ruleEnabled"),
    ruleProtocols: $("ruleProtocols"),
    ruleRiskWarning: $("ruleRiskWarning"),

    // rule lists + bulk
    ruleIpv4List: $("ruleIpv4List"),
    ruleIpv6List: $("ruleIpv6List"),
    ruleDomainsList: $("ruleDomainsList"),
    rulePortsList: $("rulePortsList"),
    btnRuleAddV4: $("btnRuleAddV4"),
    btnRuleAddV6: $("btnRuleAddV6"),
    btnRuleAddDomain: $("btnRuleAddDomain"),
    btnRuleAddPort: $("btnRuleAddPort"),
    ruleIpv4Bulk: $("ruleIpv4Bulk"),
    ruleIpv6Bulk: $("ruleIpv6Bulk"),
    ruleDomainsBulk: $("ruleDomainsBulk"),
    rulePortsBulk: $("rulePortsBulk"),

    // injection
    childInjection: $("childInjection"),
    childInjectionMode: $("childInjectionMode"),
    btnTargetProcessesAdd: $("btnTargetProcessesAdd"),
    btnChildExcludeAdd: $("btnChildExcludeAdd"),
    targetProcessesList: $("targetProcessesList"),
    childInjectionExcludeList: $("childInjectionExcludeList"),

    // diagnostics
    testHost: $("testHost"),
    testPort: $("testPort"),
    testProto: $("testProto"),
    btnTest: $("btnTest"),
    testResult: $("testResult"),

    // error blocks
    err: {
      proxyType: $("err_proxyType"),
      proxyHost: $("err_proxyHost"),
      proxyPort: $("err_proxyPort"),
      logLevel: $("err_logLevel"),
      fakeIpCidr: $("err_fakeIpCidr"),
      timeoutConnect: $("err_timeoutConnect"),
      timeoutSend: $("err_timeoutSend"),
      timeoutRecv: $("err_timeoutRecv"),
      dnsMode: $("err_dnsMode"),
      ipv6Mode: $("err_ipv6Mode"),
      udpMode: $("err_udpMode"),
      allowedPorts: $("err_allowedPorts"),
      childInjectionMode: $("err_childInjectionMode"),
      ruleName: $("err_ruleName"),
    },
  };

  // -------------------------
  // Rendering
  // -------------------------
  const renderDirtyBadge = () => {
    if (!el.dirtyBadge) return;
    el.dirtyBadge.classList.toggle("hidden", !state.dirty);
  };

  const renderNav = () => {
    if (!el.sideNav) return;
    $$("button.nav-item", el.sideNav).forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.section === state.currentSection);
    });
  };

  const renderPanels = () => {
    el.panels.forEach((p) => {
      const name = p.getAttribute("data-section-panel");
      p.classList.toggle("hidden", name !== state.currentSection);
    });
  };

  const renderStatus = () => {
    if (el.configStatus) {
      el.configStatus.textContent = state.loadedName ? `已载入：${state.loadedName}` : "未导入配置（可直接恢复默认）";
    }
    if (el.configSummary) {
      const cfg = state.draft;
      const ports = cfg.proxy_rules.allowed_ports.length ? cfg.proxy_rules.allowed_ports.join(",") : "空(=全部)";
      const proxyOn = cfg.proxy.port !== 0;
      el.configSummary.textContent =
        `proxy=${proxyOn ? `${cfg.proxy.type}://${cfg.proxy.host}:${cfg.proxy.port}` : "(禁用)"}` +
        ` | fake_ip=${cfg.fake_ip.enabled ? "on" : "off"}` +
        ` | dns_mode=${cfg.proxy_rules.dns_mode}` +
        ` | ipv6_mode=${cfg.proxy_rules.ipv6_mode}` +
        ` | udp_mode=${cfg.proxy_rules.udp_mode}` +
        ` | allowed_ports=${ports}`;
    }
  };

  const renderRuntimeBehaviorHint = () => {
    if (!el.runtimeBehaviorHint) return;
    const cfg = state.draft;
    const proxyOn = cfg.proxy.port !== 0;
    const allowedPorts = cfg.proxy_rules.allowed_ports;
    const portsDesc = allowedPorts.length ? allowedPorts.join(", ") : "空(=全部端口可走代理)";

    const lines = [
      `- 代理开关：${proxyOn ? "开启" : "关闭（proxy.port=0）"}`,
      `- DNS(53)策略：dns_mode=${cfg.proxy_rules.dns_mode}（仅影响目标端口=53 的连接阶段决策）`,
      `- 端口白名单：allowed_ports=${portsDesc}（不在白名单则强制直连）`,
      `- IPv6 策略：ipv6_mode=${cfg.proxy_rules.ipv6_mode}（纯 IPv6 连接会先按此决策；仅 proxy 才进入 routing）`,
      `- UDP 策略：udp_mode=${cfg.proxy_rules.udp_mode}（proxy 开启时默认阻断 UDP，放行例外：loopback/53）`,
      "",
      "Connect 阶段简化优先级（用于理解 UI 行为）：",
      "1) routing 命中 direct → 直连",
      "2) port=53 且 dns_mode=direct → 直连",
      "3) 端口不在 allowed_ports → 直连",
      "4) proxy.port=0 → 直连",
      "5) 其它 → 走代理并握手",
    ];
    el.runtimeBehaviorHint.textContent = lines.join("\n");
  };

  const setFieldError = (key, msg) => {
    const box = el.err[key];
    if (!box) return;
    box.textContent = msg || "";
  };

  const renderValidation = () => {
    const { errors } = validateDraft(state.draft);
    for (const k of Object.keys(el.err)) {
      setFieldError(k, errors[k] || "");
    }
    // allowedPorts is rendered as list; keep aggregated error too
    if (el.err.allowedPorts) {
      setFieldError("allowedPorts", errors.allowedPorts || "");
    }
  };

  const renderProxy = () => {
    const cfg = state.draft;
    const proxyOn = cfg.proxy.port !== 0;
    if (el.proxyEnabled) el.proxyEnabled.checked = proxyOn;
    if (el.proxyType) el.proxyType.value = cfg.proxy.type;
    if (el.proxyHost) el.proxyHost.value = cfg.proxy.host;
    if (el.proxyPort) el.proxyPort.value = String(cfg.proxy.port);

    // disable fields when proxy disabled
    const disabled = !proxyOn;
    if (el.proxyType) el.proxyType.disabled = disabled;
    if (el.proxyHost) el.proxyHost.disabled = disabled;
    if (el.proxyPort) el.proxyPort.disabled = false; // allow set 0

    if (el.proxyDetectBadge) {
      el.proxyDetectBadge.textContent = proxyOn ? "PROXY=ON" : "PROXY=OFF";
    }
  };

  const renderLogging = () => {
    const cfg = state.draft;
    if (el.logLevel) el.logLevel.value = cfg.log_level;
    if (el.trafficLogging) el.trafficLogging.checked = !!cfg.traffic_logging;
  };

  const renderNetworkPolicy = () => {
    const cfg = state.draft;
    if (el.fakeIpEnabled) el.fakeIpEnabled.checked = !!cfg.fake_ip.enabled;
    if (el.fakeIpCidr) el.fakeIpCidr.value = cfg.fake_ip.cidr;

    if (el.timeoutConnect) el.timeoutConnect.value = String(cfg.timeout.connect);
    if (el.timeoutSend) el.timeoutSend.value = String(cfg.timeout.send);
    if (el.timeoutRecv) el.timeoutRecv.value = String(cfg.timeout.recv);

    if (el.dnsMode) el.dnsMode.value = cfg.proxy_rules.dns_mode;
    if (el.ipv6Mode) el.ipv6Mode.value = cfg.proxy_rules.ipv6_mode;
    if (el.udpMode) el.udpMode.value = cfg.proxy_rules.udp_mode;

    renderAllowedPortsList();
  };

  const renderAllowedPortsList = () => {
    if (!el.allowedPortsList) return;
    const ports = state.draft.proxy_rules.allowed_ports;
    el.allowedPortsList.innerHTML = "";

    if (!ports.length) {
      const hint = document.createElement("div");
      hint.className = "text-xs text-ag-muted";
      hint.textContent = "当前为空：表示允许所有端口走代理。";
      el.allowedPortsList.appendChild(hint);
      return;
    }

    ports.forEach((p, idx) => {
      const row = document.createElement("div");
      row.className = "flex items-center gap-2";

      const input = document.createElement("input");
      input.type = "number";
      input.value = String(p);
      input.placeholder = "1-65535";
      input.className = "flex-1";
      input.addEventListener(
        "input",
        debounce(() => {
          const v = normalizeInt(input.value, NaN);
          if (Number.isFinite(v)) {
            state.draft.proxy_rules.allowed_ports[idx] = v;
            markDirty();
            renderValidation();
          }
        }, 350)
      );

      const del = document.createElement("button");
      del.type = "button";
      del.className = "ag-btn ag-btn-danger";
      del.textContent = "删除";
      del.addEventListener("click", () => {
        state.draft.proxy_rules.allowed_ports.splice(idx, 1);
        markDirty();
        // 规范化：排序去重 + 过滤非法
        state.draft.proxy_rules.allowed_ports = normalizePortArray(state.draft.proxy_rules.allowed_ports);
        renderAllowedPortsList();
        renderValidation();
      });

      row.appendChild(input);
      row.appendChild(del);
      el.allowedPortsList.appendChild(row);
    });
  };

  const renderRoutingGlobal = () => {
    const rt = state.draft.proxy_rules.routing;
    if (el.routingEnabled) el.routingEnabled.checked = !!rt.enabled;
    if (el.useDefaultPrivate) el.useDefaultPrivate.checked = !!rt.use_default_private;
    if (el.priorityMode) el.priorityMode.value = rt.priority_mode;
    if (el.defaultAction) el.defaultAction.value = rt.default_action;

    if (el.priorityWarning) {
      el.priorityWarning.textContent =
        rt.priority_mode === "number"
          ? "当前为【number】模式：priority 越大越优先（稳定排序）。"
          : "当前为【order】模式：规则从上到下依次匹配，先命中者生效。";
    }
  };

  const renderRuleList = () => {
    if (!el.ruleList) return;
    if (state.isRuleListLoading) {
      el.ruleList.innerHTML = ui.renderSkeletonList(7);
      return;
    }

    const rules = state.draft.proxy_rules.routing.rules;
    el.ruleList.innerHTML = "";
    if (!rules.length) {
      const li = document.createElement("li");
      li.className = "text-xs text-ag-muted p-3";
      li.textContent = "无规则（可点“新增”）";
      el.ruleList.appendChild(li);
      return;
    }

    rules.forEach((r, idx) => {
      const li = document.createElement("li");
      li.className = `rule-item ${idx === state.selectedRuleIndex ? "active" : ""}`;
      const action = toLower(r.action || "proxy");
      const actionLabel = action === "direct" ? "DIRECT" : "PROXY";

      const name = document.createElement("span");
      name.className = "rule-item-name";
      name.title = String(r.name);
      name.textContent = `> ${String(r.name).slice(0, 80)}`;

      const badge = document.createElement("span");
      badge.className = `rule-item-badge ${action === "direct" ? "rule-item-badge--direct" : "rule-item-badge--proxy"}`;
      badge.textContent = actionLabel;

      li.appendChild(name);
      li.appendChild(badge);

      li.addEventListener("click", () => {
        if (state.selectedRuleIndex === idx) return;
        state.selectedRuleIndex = idx;
        renderRuleList();
        renderRuleEditor();
      });
      el.ruleList.appendChild(li);
    });
  };

  const getSelectedRule = () => state.draft.proxy_rules.routing.rules[state.selectedRuleIndex] || null;

  const renderRuleRiskWarning = () => {
    const box = el.ruleRiskWarning;
    if (!box) return;
    const rule = getSelectedRule();
    if (!rule || !state.draft.fake_ip.enabled) {
      box.classList.add("hidden");
      box.textContent = "";
      return;
    }
    const action = toLower(rule.action);
    const hasDomains = Array.isArray(rule.domains) && rule.domains.length > 0;
    const hasPorts = Array.isArray(rule.ports) && rule.ports.length > 0;
    if (action === "direct" && hasDomains && hasPorts) {
      box.classList.remove("hidden");
      box.innerHTML =
        "<strong>风险提示</strong><br>" +
        "当前规则为 <code>direct + domains + ports</code>。启用 FakeIP 时，该组合可能导致解析阶段与连接阶段行为不一致。" +
        " 建议：移除 <code>ports</code> 限制，或改用 CIDR/IP 规则收敛范围。";
      return;
    }
    box.classList.add("hidden");
    box.textContent = "";
  };

  const renderRuleListEditor = (container, items, { placeholder = "", onChange }) => {
    if (!container) return;
    container.innerHTML = "";
    if (!items.length) {
      const hint = document.createElement("div");
      hint.className = "text-xs text-ag-muted";
      hint.textContent = "（空）";
      container.appendChild(hint);
      return;
    }
    items.forEach((v, idx) => {
      const row = document.createElement("div");
      row.className = "flex items-center gap-2";
      const input = document.createElement("input");
      input.type = "text";
      input.value = v;
      input.placeholder = placeholder;
      input.className = "flex-1";
      input.addEventListener(
        "input",
        debounce(() => {
          items[idx] = input.value;
          onChange?.();
        }, 350)
      );
      const del = document.createElement("button");
      del.type = "button";
      del.className = "ag-btn ag-btn-danger";
      del.textContent = "删除";
      del.addEventListener("click", () => {
        items.splice(idx, 1);
        onChange?.();
      });
      row.appendChild(input);
      row.appendChild(del);
      container.appendChild(row);
    });
  };

  const renderRuleEditor = () => {
    const rule = getSelectedRule();
    if (!el.ruleEditorForm) return;
    if (!rule) {
      el.ruleEditorForm.classList.add("opacity-50", "pointer-events-none");

      // 清空显示，避免“看起来还能编辑”的错觉
      if (el.ruleName) el.ruleName.value = "";
      if (el.ruleAction) el.ruleAction.value = "proxy";
      if (el.rulePriority) el.rulePriority.value = "0";
      if (el.ruleEnabled) el.ruleEnabled.checked = false;
      if (el.ruleProtocols) el.ruleProtocols.value = "";

      const emptyList = (container, text = "请选择左侧规则或点击“新增”。") => {
        if (!container) return;
        container.innerHTML = "";
        const hint = document.createElement("div");
        hint.className = "text-xs text-ag-muted";
        hint.textContent = text;
        container.appendChild(hint);
      };
      emptyList(el.ruleIpv4List);
      emptyList(el.ruleIpv6List);
      emptyList(el.ruleDomainsList);
      emptyList(el.rulePortsList);

      if (el.ruleIpv4Bulk) el.ruleIpv4Bulk.value = "";
      if (el.ruleIpv6Bulk) el.ruleIpv6Bulk.value = "";
      if (el.ruleDomainsBulk) el.ruleDomainsBulk.value = "";
      if (el.rulePortsBulk) el.rulePortsBulk.value = "";

      return;
    }
    el.ruleEditorForm.classList.remove("opacity-50", "pointer-events-none");

    if (el.ruleName) el.ruleName.value = rule.name || "";
    if (el.ruleAction) el.ruleAction.value = rule.action || "proxy";
    if (el.rulePriority) el.rulePriority.value = String(rule.priority ?? 0);
    if (el.ruleEnabled) el.ruleEnabled.checked = !!rule.enabled;
    if (el.ruleProtocols) el.ruleProtocols.value = (rule.protocols || []).join(", ");

    // list editors
    renderRuleListEditor(el.ruleIpv4List, rule.ip_cidrs_v4 || [], {
      placeholder: "10.0.0.0/8",
      onChange: () => {
        rule.ip_cidrs_v4 = normalizeStringArray(rule.ip_cidrs_v4);
        markDirty();
        renderValidation();
      },
    });
    renderRuleListEditor(el.ruleIpv6List, rule.ip_cidrs_v6 || [], {
      placeholder: "fc00::/7",
      onChange: () => {
        rule.ip_cidrs_v6 = normalizeStringArray(rule.ip_cidrs_v6);
        markDirty();
        renderValidation();
      },
    });
    renderRuleListEditor(el.ruleDomainsList, rule.domains || [], {
      placeholder: ".local / *.example.com / *",
      onChange: () => {
        rule.domains = normalizeStringArray(rule.domains);
        markDirty();
        renderValidation();
        renderRuleRiskWarning();
      },
    });
    renderRuleListEditor(el.rulePortsList, rule.ports || [], {
      placeholder: "443 / 10000-20000",
      onChange: () => {
        rule.ports = normalizeStringArray(rule.ports);
        markDirty();
        renderValidation();
        renderRuleRiskWarning();
      },
    });

    // bulk
    if (el.ruleIpv4Bulk) el.ruleIpv4Bulk.value = (rule.ip_cidrs_v4 || []).join("\n");
    if (el.ruleIpv6Bulk) el.ruleIpv6Bulk.value = (rule.ip_cidrs_v6 || []).join("\n");
    if (el.ruleDomainsBulk) el.ruleDomainsBulk.value = (rule.domains || []).join("\n");
    if (el.rulePortsBulk) el.rulePortsBulk.value = (rule.ports || []).join("\n");

    renderRuleRiskWarning();
  };

  const renderRouting = () => {
    renderRoutingGlobal();
    renderRuleList();
    renderRuleEditor();
  };

  const renderInjectionLists = () => {
    const cfg = state.draft;

    const renderStringList = (container, items, addBtnId) => {
      if (!container) return;
      container.innerHTML = "";
      if (!items.length) {
        const hint = document.createElement("div");
        hint.className = "text-xs text-ag-muted";
        hint.textContent = "（空）";
        container.appendChild(hint);
        return;
      }
      items.forEach((v, idx) => {
        const row = document.createElement("div");
        row.className = "flex items-center gap-2";
        const input = document.createElement("input");
        input.type = "text";
        input.value = v;
        input.className = "flex-1";
        input.addEventListener(
          "input",
          debounce(() => {
            items[idx] = input.value;
            markDirty();
          }, 350)
        );
        const del = document.createElement("button");
        del.type = "button";
        del.className = "ag-btn ag-btn-danger";
        del.textContent = "删除";
        del.addEventListener("click", () => {
          items.splice(idx, 1);
          markDirty();
          renderInjectionLists();
        });
        row.appendChild(input);
        row.appendChild(del);
        container.appendChild(row);
      });
    };

    renderStringList(el.targetProcessesList, cfg.target_processes, "btnTargetProcessesAdd");
    renderStringList(el.childInjectionExcludeList, cfg.child_injection_exclude, "btnChildExcludeAdd");
  };

  const renderInjection = () => {
    const cfg = state.draft;
    if (el.childInjection) el.childInjection.checked = !!cfg.child_injection;
    if (el.childInjectionMode) el.childInjectionMode.value = cfg.child_injection_mode;
    renderInjectionLists();

    // mode=inherit 时 target_processes 不参与决策（后端直接 return true），这里做 UI 提示/弱禁用
    const inherit = cfg.child_injection_mode === "inherit";
    if (el.targetProcessesList) {
      el.targetProcessesList.classList.toggle("opacity-50", inherit);
    }
  };

  const renderProbeList = () => {
    if (!el.proxyProbeList) return;
    el.proxyProbeList.innerHTML = "";

    if (state.probe.loading) {
      const ul = document.createElement("ul");
      ul.className = "space-y-2";
      ul.innerHTML = ui.renderSkeletonList(4);
      el.proxyProbeList.appendChild(ul);
      return;
    }

    if (!state.probe.results.length) {
      const hint = document.createElement("div");
      hint.className = "text-xs text-ag-muted";
      hint.textContent = "尚未扫描。";
      el.proxyProbeList.appendChild(hint);
      return;
    }

    for (const r of state.probe.results) {
      const row = document.createElement("div");
      row.className = "flex items-center justify-between gap-3 rounded border border-ag-border bg-ag-surface2 px-3 py-2";

      const left = document.createElement("div");
      left.className = "min-w-0";
      const title = document.createElement("div");
      title.className = "truncate text-xs text-ag-textMain";
      title.textContent = `${r.label}  ${r.host}:${r.port}`;
      const sub = document.createElement("div");
      sub.className = "mt-1 text-[11px] text-ag-muted";
      sub.textContent = r.note;
      left.appendChild(title);
      left.appendChild(sub);

      const right = document.createElement("div");
      right.className = "flex shrink-0 flex-wrap items-center justify-end gap-2";

      right.appendChild(ui.tag(r.httpOk ? "HTTP✓" : "HTTP×", r.httpOk ? "info" : "muted"));
      if (!r.httpOk) right.appendChild(ui.tag("SOCKS5?", "ok"));

      const useHttp = document.createElement("button");
      useHttp.type = "button";
      useHttp.className = "ag-btn ag-btn-ghost";
      useHttp.textContent = "填入HTTP";
      useHttp.disabled = !r.httpOk;
      useHttp.addEventListener("click", () => {
        state.draft.proxy.host = r.host;
        state.draft.proxy.port = r.port;
        state.draft.proxy.type = "http";
        markDirty();
        renderProxy();
        renderValidation();
        ui.toast("已填入 HTTP 代理", "success");
      });

      const useSocks = document.createElement("button");
      useSocks.type = "button";
      useSocks.className = "ag-btn ag-btn-ghost";
      useSocks.textContent = "填入SOCKS5";
      useSocks.addEventListener("click", () => {
        state.draft.proxy.host = r.host;
        state.draft.proxy.port = r.port;
        state.draft.proxy.type = "socks5";
        markDirty();
        renderProxy();
        renderValidation();
        ui.toast("已填入 SOCKS5 代理（候选）", "success");
      });

      right.appendChild(useHttp);
      right.appendChild(useSocks);

      row.appendChild(left);
      row.appendChild(right);
      el.proxyProbeList.appendChild(row);
    }
  };

  const renderDiagnostics = () => {
    // nothing to render for now
  };

  const renderAll = () => {
    renderDirtyBadge();
    renderNav();
    renderPanels();
    renderStatus();
    renderRuntimeBehaviorHint();
    renderProxy();
    renderLogging();
    renderNetworkPolicy();
    renderRouting();
    renderInjection();
    renderDiagnostics();
    renderValidation();
    renderProbeList();
  };

  // -------------------------
  // Operations
  // -------------------------
  const loadConfig = async (json, options = {}) => {
    const silent = options?.silent === true;
    const toastMessage = options?.toastMessage;
    const loadedName = options?.loadedName || "";

    state.isRuleListLoading = true;
    renderRuleList();
    await new Promise((r) => setTimeout(r, 450));

    state.baseRaw = json && typeof json === "object" ? json : {};
    state.loadedName = loadedName;
    state.draft = normalizeConfig(state.baseRaw);
    state.dirty = false;
    state.selectedRuleIndex = 0;
    state.compiledRouting = routingEngine.compileRouting(state.draft.proxy_rules.routing);

    state.isRuleListLoading = false;
    renderAll();

    if (!silent) ui.toast(toastMessage || "配置已载入", "success");
  };

  const exportConfig = async () => {
    ui.setLoading(el.btnDownload, true, "正在生成...");
    await new Promise((r) => setTimeout(r, 500));

    try {
      // 先校验
      const v = validateDraft(state.draft);
      renderValidation();
      if (!v.ok) {
        ui.toast("存在配置错误：请先修正红色提示后再导出", "error");
        return;
      }

      // 保留未知字段：从原始导入 JSON 深拷贝，再覆盖已知字段
      const out = deepClone(state.baseRaw || {});

      out.log_level = state.draft.log_level;
      out.traffic_logging = !!state.draft.traffic_logging;
      out.child_injection = !!state.draft.child_injection;
      out.child_injection_mode = state.draft.child_injection_mode;
      out.child_injection_exclude = deepClone(state.draft.child_injection_exclude);
      out.target_processes = deepClone(state.draft.target_processes);

      // 对象级覆盖：仅写入“已知字段”，未知字段保持不变
      const outProxy = ensureObjIn(out, "proxy");
      outProxy.host = state.draft.proxy.host;
      outProxy.port = state.draft.proxy.port;
      outProxy.type = state.draft.proxy.type;

      const outFakeIp = ensureObjIn(out, "fake_ip");
      outFakeIp.enabled = !!state.draft.fake_ip.enabled;
      outFakeIp.cidr = state.draft.fake_ip.cidr;

      const outTimeout = ensureObjIn(out, "timeout");
      outTimeout.connect = state.draft.timeout.connect;
      outTimeout.send = state.draft.timeout.send;
      outTimeout.recv = state.draft.timeout.recv;

      const outRules = ensureObjIn(out, "proxy_rules");
      outRules.allowed_ports = normalizePortArray(state.draft.proxy_rules.allowed_ports);
      outRules.dns_mode = state.draft.proxy_rules.dns_mode;
      outRules.ipv6_mode = state.draft.proxy_rules.ipv6_mode;
      outRules.udp_mode = state.draft.proxy_rules.udp_mode;

      const outRouting = ensureObjIn(outRules, "routing");
      outRouting.enabled = !!state.draft.proxy_rules.routing.enabled;
      outRouting.priority_mode = state.draft.proxy_rules.routing.priority_mode;
      outRouting.default_action = state.draft.proxy_rules.routing.default_action;
      outRouting.use_default_private = !!state.draft.proxy_rules.routing.use_default_private;
      outRouting.rules = deepClone(state.draft.proxy_rules.routing.rules || []);

      // 规则数组清洗：去除空白字符串，保证类型稳定
      outRouting.rules = (outRouting.rules || []).map((r, idx) => {
        const rule = { ...defaultRoutingRule(), ...(r && typeof r === "object" ? r : {}) };
        rule.name = trim(rule.name) || `rule-${idx + 1}`;
        rule.action = normalizeEnum(rule.action, ["proxy", "direct"], out.proxy_rules.routing.default_action);
        rule.priority = normalizeInt(rule.priority, 0);
        rule.enabled = normalizeBool(rule.enabled, true);
        rule.ip_cidrs_v4 = normalizeStringArray(rule.ip_cidrs_v4);
        rule.ip_cidrs_v6 = normalizeStringArray(rule.ip_cidrs_v6);
        rule.domains = normalizeStringArray(rule.domains);
        rule.ports = normalizeStringArray(rule.ports);
        rule.protocols = normalizeStringArray(rule.protocols);
        return rule;
      });

      const blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "config.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      state.dirty = false;
      renderDirtyBadge();
      ui.toast("配置文件导出成功", "success");
    } catch (e) {
      ui.toast("导出失败: " + (e?.message || String(e)), "error");
    } finally {
      ui.setLoading(el.btnDownload, false);
    }
  };

  // -------------------------
  // Proxy port probe (best-effort)
  // -------------------------
  const COMMON_PROXY_PRESETS = [
    { label: "Clash (常见) SOCKS5", host: "127.0.0.1", port: 7890 },
    { label: "Clash (常见) HTTP", host: "127.0.0.1", port: 7891 },
    { label: "V2RayN (常见) SOCKS5", host: "127.0.0.1", port: 10808 },
    { label: "V2RayN (常见) HTTP", host: "127.0.0.1", port: 10809 },
  ];

  const probeHttp = async (host, port, timeoutMs = 900) => {
    const controller = new AbortController();
    const t = window.setTimeout(() => controller.abort(), timeoutMs);
    const url = `http://${host}:${port}/`;
    try {
      // no-cors：只要能建立并收到合法 HTTP 响应，就会 resolve（返回 opaque response）
      await fetch(url, { method: "GET", mode: "no-cors", cache: "no-store", signal: controller.signal });
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: e?.name || "error" };
    } finally {
      window.clearTimeout(t);
    }
  };

  const runProxyProbe = async () => {
    if (state.probe.loading) return;
    state.probe.loading = true;
    state.probe.results = [];
    renderProbeList();

    ui.setLoading(el.btnProbePorts, true, "扫描中…");
    try {
      const results = [];
      for (const item of COMMON_PROXY_PRESETS) {
        const http = await probeHttp(item.host, item.port, 800);
        results.push({
          ...item,
          httpOk: http.ok,
          note: http.ok ? "HTTP 探测：有响应（可能是 HTTP 代理或 HTTP 服务）" : "HTTP 探测：无响应（可能是 SOCKS5/端口未开放/被拦截）",
        });
      }
      state.probe.results = results;
      renderProbeList();
      ui.toast("扫描完成（best-effort）", "success");
    } finally {
      state.probe.loading = false;
      ui.setLoading(el.btnProbePorts, false);
      renderProbeList();
    }
  };

  // -------------------------
  // Test console (simulate key policy chain)
  // -------------------------
  const isPortAllowed = (port) => {
    const list = state.draft.proxy_rules.allowed_ports;
    if (!list.length) return true;
    return list.includes(port);
  };

  const simulateConnect = (host, port, proto) => {
    const cfg = state.draft;
    const compiled = (state.compiledRouting = routingEngine.compileRouting(cfg.proxy_rules.routing));
    const r = routingEngine.matchRouting(compiled, host, "", false, port, proto);

    let final = "proxy";
    let reason = "default";

    if (cfg.proxy.port === 0) {
      final = "direct";
      reason = "proxy.port=0（禁用代理）";
    } else if (r.action === "direct") {
      final = "direct";
      reason = r.rule ? `routing 命中 direct（${r.rule}）` : "routing default_action=direct";
    } else if (port === 53 && (cfg.proxy_rules.dns_mode === "direct" || !cfg.proxy_rules.dns_mode)) {
      final = "direct";
      reason = "dns_mode=direct（port=53）";
    } else if (!isPortAllowed(port)) {
      final = "direct";
      reason = "allowed_ports 未包含该端口";
    } else {
      final = "proxy";
      reason = r.matched ? `routing 命中 proxy（${r.rule}）` : "routing 默认/未命中 → 继续走代理策略";
    }

    return { routing: r, final, reason };
  };

  const simulateDnsFakeIp = (host, proto) => {
    const cfg = state.draft;
    if (!cfg.fake_ip.enabled) {
      return { fakeip: "off", reason: "fake_ip.enabled=false" };
    }
    const compiled = (state.compiledRouting = routingEngine.compileRouting(cfg.proxy_rules.routing));
    const r = routingEngine.matchRouting(compiled, host, "", false, 0, proto);
    if (r.action === "direct") {
      return { fakeip: "bypass", reason: r.rule ? `routing direct（${r.rule}）` : "routing default_action=direct" };
    }
    return { fakeip: "on", reason: r.matched ? `routing proxy（${r.rule}）` : "routing 默认/未命中" };
  };

  const runTest = async () => {
    const host = trim(el.testHost?.value);
    if (!host) {
      ui.toast("请输入目标 Host / IP", "warning");
      return;
    }

    ui.setLoading(el.btnTest, true, "测试中…");
    await new Promise((r) => setTimeout(r, 250));

    const port = normalizeInt(el.testPort?.value || "0", 0);
    const proto = el.testProto?.value || "tcp";

    const connect = simulateConnect(host, port, proto);
    const dns = simulateDnsFakeIp(host, proto);

    const connectColor = connect.final === "direct" ? "text-ag-primary" : "text-ag-secondary";
    const connectLabel = connect.final.toUpperCase();

    const dnsLabel =
      dns.fakeip === "off" ? "FAKEIP=OFF" : dns.fakeip === "bypass" ? "FAKEIP=BYPASS" : "FAKEIP=ON";

    el.testResult.innerHTML = `
      <div class="space-y-2 text-sm">
        <div class="${connectColor}">[CONNECT] ${connectLabel} <span class="text-ag-muted">原因：${connect.reason}</span></div>
        <div class="text-ag-muted">[ROUTING] action=${(connect.routing.action || "(disabled)").toUpperCase()} rule=${connect.routing.rule || "(default/none)"} matched=${connect.routing.matched ? "true" : "false"}</div>
        <div class="text-ag-secondary">[DNS/FakeIP] ${dnsLabel} <span class="text-ag-muted">原因：${dns.reason}</span></div>
      </div>
    `;

    ui.setLoading(el.btnTest, false);
  };

  // -------------------------
  // Events
  // -------------------------
  const scheduleRecompile = debounce(() => {
    state.compiledRouting = routingEngine.compileRouting(state.draft.proxy_rules.routing);
  }, 350);

  const scheduleRerenderSummary = debounce(() => {
    renderStatus();
    renderRuntimeBehaviorHint();
  }, 350);

  const scheduleValidate = debounce(() => {
    renderValidation();
  }, 250);

  const bindEvents = () => {
    // Sidebar navigation
    if (el.sideNav) {
      $$("button.nav-item", el.sideNav).forEach((btn) => {
        btn.addEventListener("click", () => {
          state.currentSection = btn.dataset.section || "overview";
          renderNav();
          renderPanels();
        });
      });
    }

    // File import
    el.configFile?.addEventListener("change", (event) => {
      const file = event.target.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const json = JSON.parse(String(reader.result || "{}"));
          loadConfig(json, { toastMessage: "已导入配置", loadedName: file.name });
        } catch (err) {
          ui.toast("JSON 解析失败: " + (err?.message || String(err)), "error");
        }
      };
      reader.readAsText(file);
      event.target.value = "";
    });

    // Reset (danger)
    el.btnLoadExample?.addEventListener("click", async () => {
      const ok = await ui.confirmDanger("恢复默认", "将覆盖当前所有配置内容（但不会上传文件）。建议先导出一份备份。");
      if (!ok) return;
      loadConfig(defaultConfig(), { toastMessage: "已恢复默认（全量示例）", loadedName: "" });
    });

    // Export
    el.btnDownload?.addEventListener("click", () => {
      exportConfig();
    });

    // Onboarding
    const KEY = "ag_configlab_onboarding_hidden_v1";
    const applyOnboardingVisibility = () => {
      if (!el.onboardingCard) return;
      let hidden = false;
      try {
        hidden = localStorage.getItem(KEY) === "1";
      } catch (_) {
        hidden = false;
      }
      el.onboardingCard.classList.toggle("hidden", hidden);
    };
    applyOnboardingVisibility();

    el.btnOnboardingHide?.addEventListener("click", () => {
      el.onboardingCard?.classList.add("hidden");
      ui.toast("已隐藏快速入门（刷新后可能再次出现）");
    });
    el.btnOnboardingNever?.addEventListener("click", () => {
      try {
        localStorage.setItem(KEY, "1");
      } catch (_) {}
      el.onboardingCard?.classList.add("hidden");
      ui.toast("后续将不再显示快速入门", "success");
    });

    // Presets
    const PRESET_TEMPLATES = {
      clash_default: {
        name: "Clash / 通用本地代理（127.0.0.1:7890）",
        proxy: { type: "socks5", host: "127.0.0.1", port: 7890 },
        routing: {
          enabled: true,
          priority_mode: "order",
          default_action: "proxy",
          use_default_private: true,
          rules: [
            {
              name: "lan-domain-direct",
              enabled: true,
              action: "direct",
              priority: 0,
              ip_cidrs_v4: [],
              ip_cidrs_v6: [],
              domains: [".local", ".lan"],
              ports: [],
              protocols: ["tcp"],
            },
          ],
        },
      },
      https_only_proxy: {
        name: "仅代理 HTTPS（443）",
        proxy: { type: "socks5", host: "127.0.0.1", port: 7890 },
        routing: {
          enabled: true,
          priority_mode: "order",
          default_action: "direct",
          use_default_private: true,
          rules: [
            {
              name: "https-proxy",
              enabled: true,
              action: "proxy",
              priority: 0,
              ip_cidrs_v4: [],
              ip_cidrs_v6: [],
              domains: ["*"],
              ports: ["443"],
              protocols: ["tcp"],
            },
          ],
        },
      },
      lan_direct_proxy_else: {
        name: "局域网直连，其它走代理",
        proxy: { type: "socks5", host: "127.0.0.1", port: 7890 },
        routing: {
          enabled: true,
          priority_mode: "order",
          default_action: "proxy",
          use_default_private: true,
          rules: [
            {
              name: "lan-domain-direct",
              enabled: true,
              action: "direct",
              priority: 0,
              ip_cidrs_v4: [],
              ip_cidrs_v6: [],
              domains: [".local", ".lan"],
              ports: [],
              protocols: ["tcp"],
            },
          ],
        },
      },
      direct_all: {
        name: "全直连（调试）",
        proxy: { type: "socks5", host: "127.0.0.1", port: 0 },
        routing: {
          enabled: true,
          priority_mode: "order",
          default_action: "direct",
          use_default_private: false,
          rules: [],
        },
      },
    };

    const applyPresetTemplate = (id) => {
      const tpl = PRESET_TEMPLATES[id];
      if (!tpl) {
        ui.toast(`未知模板：${id}`, "error");
        return;
      }
      const ok = confirm(`应用模板【${tpl.name}】将覆盖：proxy + proxy_rules.routing。\n\n建议：先导出一份备份。\n\n是否继续？`);
      if (!ok) return;

      state.draft.proxy = deepClone(tpl.proxy);
      state.draft.proxy_rules.routing = deepClone(tpl.routing);
      state.compiledRouting = routingEngine.compileRouting(state.draft.proxy_rules.routing);
      state.selectedRuleIndex = 0;
      markDirty();
      renderAll();
      ui.toast(`已应用模板：${tpl.name}`, "success");
    };

    el.presetButtons.forEach((btn) => {
      btn.addEventListener("click", () => applyPresetTemplate(btn.dataset.template));
    });

    // Proxy probe
    el.btnProbePorts?.addEventListener("click", () => runProxyProbe());

    // Simple bindings (proxy/logging/network/injection/routing global)
    const bind = (node, eventName, handler) => {
      if (!node) return;
      node.addEventListener(eventName, handler);
    };

    // proxy enabled
    bind(el.proxyEnabled, "change", () => {
      const on = !!el.proxyEnabled.checked;
      if (on && state.draft.proxy.port === 0) state.draft.proxy.port = 7890;
      if (!on) state.draft.proxy.port = 0;
      markDirty();
      renderProxy();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.proxyType, "change", () => {
      state.draft.proxy.type = toLower(el.proxyType.value);
      markDirty();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.proxyHost, "input", debounce(() => {
      state.draft.proxy.host = trim(el.proxyHost.value) || "127.0.0.1";
      markDirty();
      scheduleValidate();
      scheduleRerenderSummary();
    }, 350));
    bind(el.proxyPort, "input", debounce(() => {
      const v = normalizeInt(el.proxyPort.value, 0);
      state.draft.proxy.port = v;
      markDirty();
      renderProxy(); // refresh enabled/disabled state
      scheduleValidate();
      scheduleRerenderSummary();
    }, 350));

    // log level + traffic logging
    bind(el.logLevel, "change", () => {
      state.draft.log_level = toLower(el.logLevel.value);
      markDirty();
      scheduleValidate();
    });
    bind(el.trafficLogging, "change", () => {
      state.draft.traffic_logging = !!el.trafficLogging.checked;
      markDirty();
    });

    // fake ip
    bind(el.fakeIpEnabled, "change", () => {
      state.draft.fake_ip.enabled = !!el.fakeIpEnabled.checked;
      markDirty();
      renderRuleRiskWarning();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.fakeIpCidr, "input", debounce(() => {
      state.draft.fake_ip.cidr = trim(el.fakeIpCidr.value) || "198.18.0.0/15";
      markDirty();
      scheduleValidate();
    }, 350));

    // timeout
    bind(el.timeoutConnect, "input", debounce(() => {
      state.draft.timeout.connect = Math.max(1, normalizeInt(el.timeoutConnect.value, 5000));
      markDirty();
      scheduleValidate();
    }, 350));
    bind(el.timeoutSend, "input", debounce(() => {
      state.draft.timeout.send = Math.max(1, normalizeInt(el.timeoutSend.value, 5000));
      markDirty();
      scheduleValidate();
    }, 350));
    bind(el.timeoutRecv, "input", debounce(() => {
      state.draft.timeout.recv = Math.max(1, normalizeInt(el.timeoutRecv.value, 5000));
      markDirty();
      scheduleValidate();
    }, 350));

    // proxy_rules
    bind(el.dnsMode, "change", () => {
      state.draft.proxy_rules.dns_mode = toLower(el.dnsMode.value);
      markDirty();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.ipv6Mode, "change", () => {
      state.draft.proxy_rules.ipv6_mode = toLower(el.ipv6Mode.value);
      markDirty();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.udpMode, "change", () => {
      state.draft.proxy_rules.udp_mode = toLower(el.udpMode.value);
      markDirty();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.btnAllowedPortsAdd, "click", () => {
      state.draft.proxy_rules.allowed_ports.push(443);
      state.draft.proxy_rules.allowed_ports = normalizePortArray(state.draft.proxy_rules.allowed_ports);
      markDirty();
      renderAllowedPortsList();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.btnAllowedPortsClear, "click", () => {
      state.draft.proxy_rules.allowed_ports = [];
      markDirty();
      renderAllowedPortsList();
      scheduleValidate();
      scheduleRerenderSummary();
    });

    // routing global
    bind(el.routingEnabled, "change", () => {
      state.draft.proxy_rules.routing.enabled = !!el.routingEnabled.checked;
      markDirty();
      scheduleRecompile();
      scheduleRerenderSummary();
    });
    bind(el.useDefaultPrivate, "change", () => {
      state.draft.proxy_rules.routing.use_default_private = !!el.useDefaultPrivate.checked;
      markDirty();
      scheduleRecompile();
      scheduleRerenderSummary();
    });
    bind(el.priorityMode, "change", () => {
      state.draft.proxy_rules.routing.priority_mode = toLower(el.priorityMode.value);
      markDirty();
      scheduleRecompile();
      renderRoutingGlobal();
      renderRuleList();
      scheduleValidate();
      scheduleRerenderSummary();
    });
    bind(el.defaultAction, "change", () => {
      state.draft.proxy_rules.routing.default_action = toLower(el.defaultAction.value);
      markDirty();
      scheduleRecompile();
      scheduleValidate();
      scheduleRerenderSummary();
    });

    // routing rule management
    bind(el.btnAddRule, "click", () => {
      state.draft.proxy_rules.routing.rules.push(defaultRoutingRule());
      state.selectedRuleIndex = state.draft.proxy_rules.routing.rules.length - 1;
      markDirty();
      renderRuleList();
      renderRuleEditor();
      ui.toast("已新增规则", "success");
    });
    bind(el.btnCloneRule, "click", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      const clone = deepClone(rule);
      clone.name = `${rule.name || "rule"}-副本`;
      state.draft.proxy_rules.routing.rules.push(clone);
      state.selectedRuleIndex = state.draft.proxy_rules.routing.rules.length - 1;
      markDirty();
      renderRuleList();
      renderRuleEditor();
      ui.toast("已复制规则", "success");
    });
    bind(el.btnMoveUp, "click", () => {
      if (state.selectedRuleIndex <= 0) return;
      const rules = state.draft.proxy_rules.routing.rules;
      const i = state.selectedRuleIndex;
      [rules[i - 1], rules[i]] = [rules[i], rules[i - 1]];
      state.selectedRuleIndex--;
      markDirty();
      renderRuleList();
    });
    bind(el.btnMoveDown, "click", () => {
      const rules = state.draft.proxy_rules.routing.rules;
      if (state.selectedRuleIndex >= rules.length - 1) return;
      const i = state.selectedRuleIndex;
      [rules[i + 1], rules[i]] = [rules[i], rules[i + 1]];
      state.selectedRuleIndex++;
      markDirty();
      renderRuleList();
    });
    bind(el.btnDeleteRule, "click", async () => {
      const rules = state.draft.proxy_rules.routing.rules;
      if (!rules.length) return;
      const rule = getSelectedRule();
      const name = rule?.name || "未命名规则";
      const ok = await ui.confirmDanger("删除路由规则", `规则【${name}】将被永久删除，无法恢复。`);
      if (!ok) return;
      rules.splice(state.selectedRuleIndex, 1);
      state.selectedRuleIndex = Math.max(0, Math.min(state.selectedRuleIndex, rules.length - 1));
      markDirty();
      renderRuleList();
      renderRuleEditor();
      ui.toast(`已删除规则：${name}`, "warning");
    });

    // routing rule fields
    bind(el.ruleName, "input", debounce(() => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.name = trim(el.ruleName.value) || "(unnamed)";
      markDirty();
      renderRuleList();
      scheduleValidate();
    }, 350));
    bind(el.ruleAction, "change", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.action = toLower(el.ruleAction.value);
      markDirty();
      renderRuleList();
      renderRuleRiskWarning();
    });
    bind(el.rulePriority, "input", debounce(() => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.priority = normalizeInt(el.rulePriority.value, 0);
      markDirty();
      renderRuleList();
    }, 350));
    bind(el.ruleEnabled, "change", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.enabled = !!el.ruleEnabled.checked;
      markDirty();
      renderRuleList();
    });
    bind(el.ruleProtocols, "input", debounce(() => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.protocols = normalizeStringArray(String(el.ruleProtocols.value).split(/[,，\n]+/));
      markDirty();
      scheduleValidate();
    }, 350));

    // rule add buttons
    bind(el.btnRuleAddV4, "click", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.ip_cidrs_v4 = rule.ip_cidrs_v4 || [];
      rule.ip_cidrs_v4.push("");
      markDirty();
      renderRuleEditor();
    });
    bind(el.btnRuleAddV6, "click", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.ip_cidrs_v6 = rule.ip_cidrs_v6 || [];
      rule.ip_cidrs_v6.push("");
      markDirty();
      renderRuleEditor();
    });
    bind(el.btnRuleAddDomain, "click", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.domains = rule.domains || [];
      rule.domains.push("");
      markDirty();
      renderRuleEditor();
    });
    bind(el.btnRuleAddPort, "click", () => {
      const rule = getSelectedRule();
      if (!rule) return;
      rule.ports = rule.ports || [];
      rule.ports.push("");
      markDirty();
      renderRuleEditor();
    });

    // bulk paste -> list
    const bindBulk = (textarea, key) => {
      if (!textarea) return;
      textarea.addEventListener(
        "input",
        debounce(() => {
          const rule = getSelectedRule();
          if (!rule) return;
          const list = String(textarea.value || "")
            .split(/[\n,，]+/)
            .map((x) => x.trim())
            .filter(Boolean);
          rule[key] = list;
          markDirty();
          renderRuleEditor();
        }, 450)
      );
    };
    bindBulk(el.ruleIpv4Bulk, "ip_cidrs_v4");
    bindBulk(el.ruleIpv6Bulk, "ip_cidrs_v6");
    bindBulk(el.ruleDomainsBulk, "domains");
    bindBulk(el.rulePortsBulk, "ports");

    // injection settings
    bind(el.childInjection, "change", () => {
      state.draft.child_injection = !!el.childInjection.checked;
      markDirty();
      scheduleValidate();
    });
    bind(el.childInjectionMode, "change", () => {
      state.draft.child_injection_mode = toLower(el.childInjectionMode.value);
      markDirty();
      renderInjection();
      scheduleValidate();
    });
    bind(el.btnTargetProcessesAdd, "click", () => {
      state.draft.target_processes.push("");
      markDirty();
      renderInjectionLists();
    });
    bind(el.btnChildExcludeAdd, "click", () => {
      state.draft.child_injection_exclude.push("");
      markDirty();
      renderInjectionLists();
    });

    // test
    bind(el.btnTest, "click", () => runTest());
  };

  // -------------------------
  // Init
  // -------------------------
  const init = () => {
    // 默认载入（静默）
    loadConfig(defaultConfig(), { silent: true, loadedName: "" });
    bindEvents();
    // 默认激活 overview
    state.currentSection = "overview";
    renderAll();
  };

  init();
})();

