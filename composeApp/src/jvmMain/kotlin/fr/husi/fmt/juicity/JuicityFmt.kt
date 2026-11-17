package fr.husi.fmt.juicity

import fr.husi.database.DataStore
import fr.husi.database.preference.getBlocking
import fr.husi.fmt.LOCALHOST4
import fr.husi.fmt.SingBoxOptions
import fr.husi.fmt.protectPath
import fr.husi.ktx.blankAsNull
import fr.husi.ktx.parseBoolean
import fr.husi.ktx.toJsonStringKxs
import io.github.xchacha20_poly1305.kpuri.Url
import io.github.xchacha20_poly1305.kpuri.buildUrl
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

// https://github.com/juicity/juicity/blob/4af4f68b405a6b86560ebb16963d133a7196af5c/README.md
fun parseJuicity(link: String): JuicityBean {
    val url = Url.parse(link)
    return JuicityBean().apply {
        name = url.fragment.orEmpty()
        uuid = url.username.orEmpty()
        password = url.password.orEmpty()
        serverAddress = url.host.orEmpty()
        val portField = url.port.orEmpty()
        if (portField.contains('-') || portField.contains(',')) {
            serverPorts = portField
            serverPort = portField
                .split(',', '-')
                .map { it.trim() }
                .firstOrNull { it.isNotEmpty() }
                ?.toIntOrNull()
                ?: 443
        } else {
            serverPort = portField.toIntOrNull() ?: 443
            serverPorts = serverPort.toString()
        }

        sni = url.queryParameter("sni").orEmpty()
        allowInsecure = url.parseBoolean("allow_insecure")
        pinSHA256 = url.queryParameter("pinned_certchain_sha256").orEmpty()
        // 兼容 server_ports / ports 查询参数
        serverPorts = url.queryParameter("server_ports").orEmpty()
            .ifBlank { url.queryParameter("ports").orEmpty() }
            .ifBlank { serverPorts }
        hopInterval = url.queryParameter("hop_interval").orEmpty().ifBlank { "30s" }
    }
}

fun JuicityBean.toUri(): String = buildUrl("juicity") {
    username = uuid
    password = this@toUri.password
    host = serverAddress
    val ports = serverPorts.ifBlank { serverPort.toString() }
    port = ports

    addQueryParameter("congestion_control", "bbr")
    if (sni.isNotBlank()) addQueryParameter("sni", sni)
    if (allowInsecure) addQueryParameter("allow_insecure", "1")
    if (pinSHA256.isNotBlank()) addQueryParameter("pinned_certchain_sha256", pinSHA256)
    if (ports.contains('-') || ports.contains(',')) {
        addQueryParameter("server_ports", ports)
        addQueryParameter("ports", ports)
        val interval = hopInterval.ifBlank { "30s" }
        addQueryParameter("hop_interval", interval)
    }
}.toString()

/**
 * 生成 juicity-client 插件配置。
 * 与可用 Windows 客户端对齐：
 * - ports: "3000-3100"
 * - hop_interval: 数字秒（如 10）
 * 同时写入 server_ports，兼容旧字段。
 */
fun JuicityBean.buildJuicityConfig(port: Int, shouldProtect: Boolean): String {
    val portsSpec = serverPorts.ifBlank { serverPort.toString() }
    val hopping = portsSpec.contains('-') || portsSpec.contains(',')
    val hopSeconds = parseHopIntervalSeconds(hopInterval)

    return buildJsonObject {
        put("listen", "$LOCALHOST4:$port")

        if (hopping) {
            // Windows 风格：server 可为纯主机；ports 提供范围
            put("server", serverAddress)
            put("ports", portsSpec)
            put("server_ports", portsSpec)
            put("hop_interval", hopSeconds)
        } else {
            put("server", pluginDialAddress())
        }

        put("uuid", uuid)
        put("password", password)
        put("sni", pluginServerName(sni))
        if (allowInsecure) {
            put("allow_insecure", true)
        }
        put("congestion_control", "bbr")
        pinSHA256.blankAsNull()?.let {
            put("pinned_certchain_sha256", it)
        }
        if (shouldProtect) {
            put("protect_path", protectPath)
        }
        put(
            "log_level",
            if (DataStore.logLevel.getBlocking() > 0) {
                "debug"
            } else {
                "error"
            },
        )
    }.toJsonStringKxs()
}

/** "30s" / "30" / "1m" -> 秒；默认 30 */
private fun parseHopIntervalSeconds(raw: String): Int {
    val s = raw.trim().ifBlank { "30s" }
    s.toIntOrNull()?.let { return it.coerceAtLeast(5) }
    if (s.endsWith("ms", ignoreCase = true)) {
        val n = s.dropLast(2).trim().toLongOrNull() ?: return 30
        return (n / 1000).toInt().coerceAtLeast(5)
    }
    if (s.endsWith("s", ignoreCase = true) && !s.endsWith("ms", ignoreCase = true)) {
        val n = s.dropLast(1).trim().toIntOrNull() ?: return 30
        return n.coerceAtLeast(5)
    }
    if (s.endsWith("m", ignoreCase = true)) {
        val n = s.dropLast(1).trim().toIntOrNull() ?: return 30
        return (n * 60).coerceAtLeast(5)
    }
    return 30
}

fun buildSingBoxOutboundJuicityBean(bean: JuicityBean): SingBoxOptions.Outbound_JuicityOptions {
    return SingBoxOptions.Outbound_JuicityOptions().apply {
        type = SingBoxOptions.TYPE_JUICITY
        server = bean.serverAddress
        server_port = bean.serverPort
        uuid = bean.uuid
        password = bean.password
        pin_cert_sha256 = bean.pinSHA256.blankAsNull()
        tls = SingBoxOptions.OutboundTLSOptions().apply {
            enabled = true
            server_name = bean.sni.blankAsNull()
            insecure = bean.allowInsecure || pin_cert_sha256 != null
        }
    }
}
