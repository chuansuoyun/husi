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
        serverPorts = url.queryParameter("server_ports").orEmpty().ifBlank { serverPorts }
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
        val interval = hopInterval.ifBlank { "30s" }
        addQueryParameter("hop_interval", interval)
    }
}.toString()

fun JuicityBean.buildJuicityConfig(port: Int, shouldProtect: Boolean): String {
    val portsSpec = serverPorts.ifBlank { serverPort.toString() }
    val hopping = portsSpec.contains('-') || portsSpec.contains(',')

    return buildJsonObject {
        put("listen", "$LOCALHOST4:$port")
        // pluginDialAddress uses finalAddress:finalPort (first port); client expands server_ports
        put("server", pluginDialAddress())
        if (hopping) {
            put("server_ports", portsSpec)
            put("hop_interval", hopInterval.ifBlank { "30s" })
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
