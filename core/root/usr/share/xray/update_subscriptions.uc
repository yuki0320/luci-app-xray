#!/usr/bin/ucode
"use strict";

import { md5 } from "digest";
import { mkstemp } from "fs";
import { cursor } from "uci";
import { urldecode, urldecode_params } from "luci.http";

const CONFIG = "xray_core";
const DEFAULT_USER_AGENT = "Wget/1.21 (luci-app-xray)";
const MANAGED_FIELDS = [
    "alias",
    "server",
    "server_port",
    "username",
    "password",
    "protocol",
    "transport",
    "vless_encryption",
    "vless_tls",
    "vless_flow_tls",
    "vless_flow_reality",
    "vless_reality_fingerprint",
    "vless_reality_server_name",
    "vless_reality_public_key",
    "vless_reality_short_id",
    "vless_spider_x",
    "vless_tls_host",
    "vless_tls_insecure",
    "vless_tls_fingerprint",
    "vless_tls_alpn",
    "vmess_security",
    "vmess_alter_id",
    "vmess_tls",
    "vmess_tls_host",
    "vmess_tls_insecure",
    "vmess_tls_fingerprint",
    "vmess_tls_alpn",
    "trojan_tls",
    "trojan_tls_host",
    "trojan_tls_insecure",
    "trojan_tls_fingerprint",
    "trojan_tls_alpn",
    "shadowsocks_security",
    "shadowsocks_udp_over_tcp",
    "tcp_guise",
    "http_host",
    "http_path",
    "ws_host",
    "ws_path",
    "h2_host",
    "h2_path",
    "grpc_service_name",
    "httpupgrade_host",
    "httpupgrade_path",
    "splithttp_host",
    "splithttp_path",
    "subscription_managed",
    "subscription_group",
    "subscription_source"
];

function shell_quote(value) {
    return "'" + replace(value, "'", "'\\''") + "'";
}

function run_command(command) {
    const stdout_file = mkstemp();
    const stderr_file = mkstemp();
    const exit_code = system(`${command} >&${stdout_file.fileno()} 2>&${stderr_file.fileno()}`);

    stdout_file.seek(0);
    stderr_file.seek(0);

    const stdout = stdout_file.read(1024 * 1024) || "";
    const stderr = stderr_file.read(1024 * 1024) || "";

    stdout_file.close();
    stderr_file.close();

    return {
        code: exit_code,
        stdout: stdout,
        stderr: stderr
    };
}

function fetch_url(url, user_agent) {
    const result = run_command(`/usr/bin/wget -qO- --timeout=15 --user-agent ${shell_quote(user_agent || DEFAULT_USER_AGENT)} ${shell_quote(url)}`);
    if (result.code !== 0) {
        return null;
    }
    return trim(result.stdout);
}

function decode_base64(value) {
    if (!value || type(value) != "string") {
        return null;
    }
    let normalized = trim(value);
    normalized = replace(normalized, /_/g, "/");
    normalized = replace(normalized, /-/g, "+");
    const padding = length(normalized) % 4;
    if (padding) {
        normalized = normalized + substr("====", padding);
    }
    return b64dec(normalized);
}

function parse_url_like(value) {
    if (!value || type(value) != "string") {
        return null;
    }

    let result = {
        searchParams: {}
    };
    let working = trim(value);

    working = replace(working, /#(.+)$/, function(_, label) {
        result["hash"] = label;
        return "";
    });

    working = replace(working, /\?(.+)$/, function(_, search) {
        result["search"] = search;
        result["searchParams"] = urldecode_params(search);
        return "";
    });

    working = replace(working, /^\/\/([^\/]+)(.*)$/, function(_, authority, path) {
        result["pathname"] = path || "/";

        authority = replace(authority, /^(.+)@([^@]+)$/, function(_, userinfo, hostinfo) {
            result["userinfo"] = userinfo;
            return hostinfo;
        });

        if (substr(authority, 0, 1) == "[") {
            authority = replace(authority, /^\[([^\]]+)\](?::(\d+))?$/, function(_, host, port) {
                result["hostname"] = host;
                result["port"] = port;
                return "";
            });
        } else {
            authority = replace(authority, /^([^:]+)(?::(\d+))?$/, function(_, host, port) {
                result["hostname"] = host;
                result["port"] = port;
                return "";
            });
        }
        return "";
    });

    if (!result["hostname"]) {
        return null;
    }

    if (result["userinfo"]) {
        replace(result["userinfo"], /^([^:]+):(.*)$/, function(_, username, password) {
            result["username"] = username;
            result["password"] = password;
            return "";
        });
        if (!result["username"]) {
            result["username"] = result["userinfo"];
        }
    }

    return result;
}

function decode_label(value) {
    if (!value) {
        return null;
    }
    return urldecode(value);
}

function normalize_transport(transport) {
    switch (transport || "tcp") {
        case "tcp":
        case "ws":
        case "grpc":
        case "httpupgrade":
            return transport || "tcp";
        case "http":
        case "h2":
            return "h2";
        case "xhttp":
        case "splithttp":
            return "splithttp";
    }
    return null;
}

function host_array(value) {
    if (!value) {
        return null;
    }
    return filter(map(split(urldecode(value), ","), trim), v => v != "");
}

function path_array(value) {
    if (!value) {
        return null;
    }
    return filter(map(split(urldecode(value), ","), trim), v => v != "");
}

function default_alias(host, port) {
    return `${host}:${port}`;
}

function finalize_node(node) {
    if (!node || !node["server"] || !node["server_port"]) {
        return null;
    }
    node["server"] = replace(node["server"], /\[|\]/g, "");
    if (!node["alias"]) {
        node["alias"] = default_alias(node["server"], node["server_port"]);
    }
    return node;
}

function apply_transport_settings(node, transport, params) {
    switch (transport) {
        case "tcp":
            if (params["headerType"] == "http") {
                node["tcp_guise"] = "http";
                node["http_host"] = host_array(params["host"]);
                node["http_path"] = path_array(params["path"]);
            } else {
                node["tcp_guise"] = "none";
            }
            break;
        case "ws":
            node["ws_host"] = params["host"] ? urldecode(params["host"]) : null;
            node["ws_path"] = params["path"] ? urldecode(params["path"]) : null;
            break;
        case "grpc":
            node["grpc_service_name"] = params["serviceName"] ? urldecode(params["serviceName"]) : null;
            break;
        case "h2":
            node["h2_host"] = host_array(params["host"]);
            node["h2_path"] = params["path"] ? urldecode(params["path"]) : null;
            break;
        case "httpupgrade":
            node["httpupgrade_host"] = params["host"] ? urldecode(params["host"]) : null;
            node["httpupgrade_path"] = params["path"] ? urldecode(params["path"]) : null;
            break;
        case "splithttp":
            node["splithttp_host"] = params["host"] ? urldecode(params["host"]) : null;
            node["splithttp_path"] = params["path"] ? urldecode(params["path"]) : null;
            break;
    }
}

function parse_vless(link, allow_insecure) {
    const parsed = parse_url_like("//" + link);
    if (!parsed || !parsed["username"]) {
        return null;
    }

    const params = parsed["searchParams"] || {};
    const transport = normalize_transport(params["type"]);
    if (!transport) {
        return null;
    }

    let node = {
        alias: decode_label(parsed["hash"]),
        server: parsed["hostname"],
        server_port: parsed["port"] || "80",
        protocol: "vless",
        password: urldecode(parsed["username"]),
        transport: transport,
        vless_encryption: params["encryption"] ? urldecode(params["encryption"]) : "none"
    };

    switch (params["security"]) {
        case "reality":
            node["vless_tls"] = "reality";
            node["vless_flow_reality"] = params["flow"] || "none";
            node["vless_reality_fingerprint"] = params["fp"] || "chrome";
            node["vless_reality_server_name"] = params["sni"] ? urldecode(params["sni"]) : null;
            node["vless_reality_public_key"] = params["pbk"] ? urldecode(params["pbk"]) : null;
            node["vless_reality_short_id"] = params["sid"] ? urldecode(params["sid"]) : null;
            node["vless_spider_x"] = params["spx"] ? urldecode(params["spx"]) : null;
            break;
        case "tls":
        case "xtls":
            node["vless_tls"] = "tls";
            node["vless_flow_tls"] = params["flow"] || "none";
            node["vless_tls_host"] = params["sni"] ? urldecode(params["sni"]) : null;
            node["vless_tls_fingerprint"] = params["fp"] ? urldecode(params["fp"]) : null;
            node["vless_tls_alpn"] = params["alpn"] ? host_array(params["alpn"]) : null;
            if (allow_insecure == "1") {
                node["vless_tls_insecure"] = "1";
            }
            break;
        default:
            node["vless_tls"] = "none";
            break;
    }

    apply_transport_settings(node, transport, params);
    return finalize_node(node);
}

function parse_vmess(link, allow_insecure) {
    if (match(link, /&/)) {
        return null;
    }

    let raw = null;
    try {
        raw = json(decode_base64(link)) || {};
    } catch (e) {
        return null;
    }

    if (raw["v"] != "2") {
        return null;
    }

    const transport = normalize_transport(raw["net"] || "tcp");
    if (!transport) {
        return null;
    }

    let node = {
        alias: raw["ps"] ? urldecode(raw["ps"]) : null,
        server: raw["add"],
        server_port: raw["port"] || "80",
        protocol: "vmess",
        password: raw["id"],
        transport: transport,
        vmess_security: raw["scy"] || "auto",
        vmess_alter_id: raw["aid"] || "0",
        vmess_tls: raw["tls"] == "tls" ? "tls" : "none"
    };

    if (node["vmess_tls"] == "tls") {
        node["vmess_tls_host"] = raw["sni"] || raw["host"] || null;
        node["vmess_tls_fingerprint"] = raw["fp"] || null;
        node["vmess_tls_alpn"] = raw["alpn"] ? host_array(raw["alpn"]) : null;
        if (allow_insecure == "1") {
            node["vmess_tls_insecure"] = "1";
        }
    }

    if (transport == "tcp" && raw["type"] == "http") {
        node["tcp_guise"] = "http";
        node["http_host"] = raw["host"] ? host_array(raw["host"]) : null;
        node["http_path"] = raw["path"] ? path_array(raw["path"]) : null;
    } else if (transport == "h2") {
        node["h2_host"] = raw["host"] ? host_array(raw["host"]) : null;
        node["h2_path"] = raw["path"] || null;
    } else if (transport == "ws") {
        node["ws_host"] = raw["host"] || null;
        node["ws_path"] = raw["path"] || null;
    } else if (transport == "grpc") {
        node["grpc_service_name"] = raw["path"] || null;
    } else if (transport == "httpupgrade") {
        node["httpupgrade_host"] = raw["host"] || null;
        node["httpupgrade_path"] = raw["path"] || null;
    } else if (transport == "splithttp") {
        node["splithttp_host"] = raw["host"] || null;
        node["splithttp_path"] = raw["path"] || null;
    } else if (transport == "tcp") {
        node["tcp_guise"] = "none";
    }

    return finalize_node(node);
}

function parse_trojan(link, allow_insecure) {
    const parsed = parse_url_like("//" + link);
    if (!parsed || !parsed["username"]) {
        return null;
    }

    const params = parsed["searchParams"] || {};
    const transport = normalize_transport(params["type"]);
    if (!transport) {
        return null;
    }

    let node = {
        alias: decode_label(parsed["hash"]),
        server: parsed["hostname"],
        server_port: parsed["port"] || "443",
        protocol: "trojan",
        password: urldecode(parsed["username"]),
        transport: transport,
        trojan_tls: "tls",
        trojan_tls_host: params["sni"] ? urldecode(params["sni"]) : null,
        trojan_tls_fingerprint: params["fp"] ? urldecode(params["fp"]) : null,
        trojan_tls_alpn: params["alpn"] ? host_array(params["alpn"]) : null
    };

    if (allow_insecure == "1") {
        node["trojan_tls_insecure"] = "1";
    }

    apply_transport_settings(node, transport, params);
    return finalize_node(node);
}

function parse_shadowsocks(link) {
    let working = link;
    const split_hash = split(working, "#", 2);
    if (length(split_hash) == 2 && index(split_hash[0], "@") < 0) {
        const decoded = decode_base64(split_hash[0]);
        if (decoded) {
            working = decoded + "#" + split_hash[1];
        }
    } else if (length(split_hash) == 1 && index(split_hash[0], "@") < 0) {
        const decoded = decode_base64(split_hash[0]);
        if (decoded) {
            working = decoded;
        }
    }

    const parsed = parse_url_like("//" + working);
    if (!parsed) {
        return null;
    }

    let method = null;
    let password = null;
    if (parsed["username"] && parsed["password"]) {
        method = parsed["username"];
        password = urldecode(parsed["password"]);
    } else if (parsed["username"]) {
        const decoded_userinfo = decode_base64(urldecode(parsed["username"]));
        if (!decoded_userinfo) {
            return null;
        }
        const pieces = split(decoded_userinfo, ":", 2);
        method = pieces[0];
        password = pieces[1];
    }

    let node = {
        alias: decode_label(parsed["hash"]),
        server: parsed["hostname"],
        server_port: parsed["port"] || "8388",
        protocol: "shadowsocks",
        password: password,
        transport: "tcp",
        shadowsocks_security: method
    };
    return finalize_node(node);
}

function parse_shadowsocks_object(item) {
    if (!item || type(item) != "object") {
        return null;
    }
    if (!item["server"] || !item["server_port"] || !item["method"] || !item["password"]) {
        return null;
    }

    return finalize_node({
        alias: item["remarks"] || item["name"] || null,
        server: item["server"],
        server_port: `${item["server_port"]}`,
        protocol: "shadowsocks",
        password: item["password"],
        transport: "tcp",
        shadowsocks_security: item["method"]
    });
}

function parse_share_link(uri, allow_insecure) {
    if (type(uri) == "object") {
        if (uri["uri"]) {
            return parse_share_link(uri["uri"], allow_insecure);
        }
        if (uri["url"]) {
            return parse_share_link(uri["url"], allow_insecure);
        }
        return parse_shadowsocks_object(uri);
    }
    if (!uri || type(uri) != "string") {
        return null;
    }
    const parts = split(trim(uri), "://", 2);
    if (length(parts) != 2) {
        return null;
    }

    switch (parts[0]) {
        case "vless":
            return parse_vless(parts[1], allow_insecure);
        case "vmess":
            return parse_vmess(parts[1], allow_insecure);
        case "trojan":
            return parse_trojan(parts[1], allow_insecure);
        case "ss":
            return parse_shadowsocks(parts[1]);
    }
    return null;
}

function apply_section(uci, section_name, node) {
    uci.set(CONFIG, section_name, "servers");
    for (let field in MANAGED_FIELDS) {
        if (node[field] !== null && node[field] !== "" && !(type(node[field]) == "array" && length(node[field]) == 0)) {
            uci.set(CONFIG, section_name, field, node[field]);
        } else {
            uci.delete(CONFIG, section_name, field);
        }
    }
}

function load_existing_nodes(config) {
    let existing = {};
    for (let section in values(config)) {
        if (section[".type"] != "servers" || section["subscription_managed"] != "1") {
            continue;
        }
        const group = section["subscription_group"];
        if (!existing[group]) {
            existing[group] = {};
        }
        existing[group][section[".name"]] = true;
    }
    return existing;
}

function read_general_config(config) {
    return filter(values(config), section => section[".type"] == "general")[0] || {};
}

function main() {
    const uci = cursor();
    uci.load(CONFIG);
    const config = uci.get_all(CONFIG) || {};
    const general = read_general_config(config);
    let subscription_urls = general["subscription_url"] || [];
    const allow_insecure = general["subscription_allow_insecure"] || "0";
    const user_agent = general["subscription_user_agent"] || DEFAULT_USER_AGENT;

    if (type(subscription_urls) != "array") {
        subscription_urls = [subscription_urls];
    }

    if (length(subscription_urls) == 0) {
        print("No subscription URL configured.\n");
        return 0;
    }

    let touched_groups = {};
    let desired_groups = {};
    let existing_groups = load_existing_nodes(config);
    let added = 0;
    let updated = 0;
    let removed = 0;

    for (let raw_url in subscription_urls) {
        const clean_url = replace(trim(raw_url), /#.*$/, "");
        if (!clean_url) {
            continue;
        }

        const group_hash = md5(clean_url);
        const response = fetch_url(clean_url, user_agent);
        if (!response) {
            continue;
        }

        let items = null;
        try {
            items = json(response);
        } catch (e) {
            const decoded = decode_base64(response);
            if (decoded) {
                items = split(trim(decoded), "\n");
            } else {
                items = split(trim(response), "\n");
            }
        }

        if (type(items) == "object" && items["servers"]) {
            items = items["servers"];
        }
        if (type(items) != "array") {
            continue;
        }

        let desired = {};
        for (let item in items) {
            const parsed = parse_share_link(item, allow_insecure);
            if (!parsed) {
                continue;
            }

            const section_name = "sub_" + md5(`${group_hash}|${parsed["alias"]}`);
            parsed["subscription_managed"] = "1";
            parsed["subscription_group"] = group_hash;
            parsed["subscription_source"] = clean_url;
            desired[section_name] = parsed;
        }

        if (length(keys(desired)) == 0) {
            continue;
        }

        touched_groups[group_hash] = true;
        desired_groups[group_hash] = desired;
    }

    for (let group_hash in keys(touched_groups)) {
        const desired = desired_groups[group_hash] || {};
        const existing = existing_groups[group_hash] || {};

        for (let section_name in keys(existing)) {
            if (!desired[section_name]) {
                uci.delete(CONFIG, section_name);
                removed++;
            }
        }

        for (let section_name in keys(desired)) {
            if (existing[section_name]) {
                updated++;
            } else {
                added++;
            }
            apply_section(uci, section_name, desired[section_name]);
        }
    }

    uci.commit(CONFIG);
    system("/etc/init.d/xray_core restart >/dev/null 2>&1");

    print(sprintf("Updated subscriptions: %d added, %d refreshed, %d removed.\n", added, updated, removed));
    return 0;
}

main();
