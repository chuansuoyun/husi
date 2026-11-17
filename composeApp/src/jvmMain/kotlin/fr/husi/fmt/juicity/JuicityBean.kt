package fr.husi.fmt.juicity

import kotlinx.serialization.Serializable as KxsSerializable
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.BeanConverters
import fr.husi.fmt.ValidateResult
import fr.husi.io.BinaryInput
import fr.husi.io.BinaryOutput
import fr.husi.ktx.joinAddress
import fr.husi.platform.PlatformInfo
import fr.husi.resources.Res
import fr.husi.resources.warn_insecure

@KxsSerializable
class JuicityBean : AbstractBean() {

    companion object {
        @JvmField
        val CREATOR = object : CREATOR<JuicityBean>() {
            override fun newInstance(): JuicityBean {
                return JuicityBean()
            }

            override fun newArray(size: Int): Array<JuicityBean?> {
                return arrayOfNulls(size)
            }
        }
    }

    var uuid: String = ""
    var password: String = ""
    var sni: String = ""
    var allowInsecure: Boolean = false

    // Only BBR???
    // https://github.com/daeuniverse/softwind/blob/6daa40f6b7a5cb9a0c44ea252e86fcb3440a7a0e/protocol/tuic/common/congestion.go#L15
    // public String congestionControl;
    var pinSHA256: String = ""

    /**
     * Single port ("443") or hop list ("20000-30000", "443,20000-20010").
     * Empty means fall back to [serverPort].
     */
    var serverPorts: String = ""

    /** e.g. "30s". Used when [serverPorts] describes more than one port. */
    var hopInterval: String = "30s"

    override val canSelfProtect get() = PlatformInfo.isAndroid || PlatformInfo.isLinux

    override fun isInsecure(): ValidateResult {
        val result = super.isInsecure()
        if (shouldReturnFromInsecureCheck(result)) return result

        if (allowInsecure) return ValidateResult.Insecure(Res.string.warn_insecure)
        return ValidateResult.Secure.Continue
    }

    override fun initializeDefaultValues() {
        super.initializeDefaultValues()
        if (serverPorts.isBlank()) {
            serverPorts = serverPort.toString()
        } else {
            val first = serverPorts
                .split(',', '-', limit = 0)
                .map { it.trim() }
                .firstOrNull { it.isNotEmpty() }
                ?.toIntOrNull()
            if (first != null && first in 1..65535) {
                serverPort = first
            }
        }
        if (hopInterval.isBlank()) {
            hopInterval = "30s"
        }
    }

    override fun displayAddress(): String {
        val ports = serverPorts.ifBlank { serverPort.toString() }
        return joinAddress(serverAddress, ports)
    }

    override fun serialize(output: BinaryOutput) {
        // version 1: serverPorts + hopInterval
        output.writeInt(1)
        super.serialize(output)
        output.writeString(uuid)
        output.writeString(password)
        output.writeString(sni)
        output.writeBoolean(allowInsecure)
        output.writeString(pinSHA256)
        output.writeString(serverPorts)
        output.writeString(hopInterval)
    }

    override fun deserialize(input: BinaryInput) {
        val version = input.readInt()
        super.deserialize(input)
        uuid = input.readString()
        password = input.readString()
        sni = input.readString()
        allowInsecure = input.readBoolean()
        pinSHA256 = input.readString()
        if (version >= 1) {
            serverPorts = input.readString()
            hopInterval = input.readString()
        } else {
            serverPorts = serverPort.toString()
            hopInterval = "30s"
        }
    }

    override fun applyFeatureSettings(other: AbstractBean) {
        if (other !is JuicityBean) return
        other.allowInsecure = allowInsecure
        other.hopInterval = hopInterval
    }

    override val defaultPort get() = 443
    override val canTCPing get() = false

    override fun clone(): JuicityBean {
        return BeanConverters.deserialize(JuicityBean(), BeanConverters.serialize(this))
    }
}
