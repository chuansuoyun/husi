package fr.husi.database

import androidx.room3.Delete
import androidx.room3.Entity
import androidx.room3.Ignore
import androidx.room3.Index
import androidx.room3.Insert
import androidx.room3.PrimaryKey
import androidx.room3.Query
import androidx.room3.Transaction
import androidx.room3.Update
import fr.husi.ProtocolProvider
import fr.husi.database.preference.getBlocking
import fr.husi.fmt.AbstractBean
import fr.husi.fmt.BeanConverters
import fr.husi.fmt.Serializable
import fr.husi.fmt.anytls.AnyTLSBean
import fr.husi.fmt.anytls.toUri
import fr.husi.fmt.buildConfig
import fr.husi.fmt.buildSingBoxOutbound
import fr.husi.fmt.config.ConfigBean
import fr.husi.fmt.direct.DirectBean
import fr.husi.fmt.http.HttpBean
import fr.husi.fmt.http.toUri
import fr.husi.fmt.hysteria.HysteriaBean
import fr.husi.fmt.hysteria.buildHysteriaConfig
import fr.husi.fmt.hysteria.canUseSingBox
import fr.husi.fmt.hysteria.toUri
import fr.husi.fmt.internal.ChainBean
import fr.husi.fmt.internal.ProxySetBean
import fr.husi.fmt.juicity.JuicityBean
import fr.husi.fmt.juicity.buildJuicityConfig
import fr.husi.fmt.juicity.toUri
import fr.husi.fmt.masque.MASQUEBean
import fr.husi.fmt.mieru.MieruBean
import fr.husi.fmt.mieru.buildMieruConfig
import fr.husi.fmt.mieru.toUri
import fr.husi.fmt.naive.NaiveBean
import fr.husi.fmt.naive.buildNaiveConfig
import fr.husi.fmt.naive.toUri
import fr.husi.fmt.shadowquic.ShadowQUICBean
import fr.husi.fmt.shadowquic.buildShadowQUICConfig
import fr.husi.fmt.shadowquic.toUri
import fr.husi.fmt.shadowsocks.ShadowsocksBean
import fr.husi.fmt.shadowsocks.toUri
import fr.husi.fmt.shadowtls.ShadowTLSBean
import fr.husi.fmt.snell.SnellBean
import fr.husi.fmt.socks.SOCKSBean
import fr.husi.fmt.socks.toUri
import fr.husi.fmt.ssh.SSHBean
import fr.husi.fmt.toUniversalLink
import fr.husi.fmt.tailscale.TailcatBean
import fr.husi.fmt.tailscale.TailscaleBean
import fr.husi.fmt.trojan.TrojanBean
import fr.husi.fmt.trusttunnel.TrustTunnelBean
import fr.husi.fmt.trusttunnel.toUri
import fr.husi.fmt.tuic.TuicBean
import fr.husi.fmt.tuic.toUri
import fr.husi.fmt.v2ray.VLESSBean
import fr.husi.fmt.v2ray.VMessBean
import fr.husi.fmt.v2ray.toUriVMessVLESSTrojan
import fr.husi.fmt.wireguard.WireGuardBean
import fr.husi.fmt.openconnect.OpenConnectBean
import fr.husi.fmt.openvpn.OpenVPNBean
import fr.husi.io.BinaryInput
import fr.husi.io.BinaryOutput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.runBlocking

@Entity(
    tableName = "proxy_entities", indices = [Index("groupId", name = "groupId")],
)
data class ProxyEntity(
    @PrimaryKey(autoGenerate = true) var id: Long = 0L,
    var groupId: Long = 0L,
    var type: Int = 0,
    var userOrder: Long = 0L,
    var tx: Long = 0L,
    var rx: Long = 0L,
    var status: Int = STATUS_INITIAL,
    var ping: Int = 0,
    var error: String? = null,
    var socksBean: SOCKSBean? = null,
    var httpBean: HttpBean? = null,
    var ssBean: ShadowsocksBean? = null,
    var vmessBean: VMessBean? = null,
    var vlessBean: VLESSBean? = null,
    var trojanBean: TrojanBean? = null,
    var mieruBean: MieruBean? = null,
    var naiveBean: NaiveBean? = null,
    var hysteriaBean: HysteriaBean? = null,
    var tuicBean: TuicBean? = null,
    var juicityBean: JuicityBean? = null,
    var sshBean: SSHBean? = null,
    var wgBean: WireGuardBean? = null,
    var openConnectBean: OpenConnectBean? = null,
    var openVPNBean: OpenVPNBean? = null,
    var masqueBean: MASQUEBean? = null,
    var tailscaleBean: TailscaleBean? = null,
    var tailcatBean: TailcatBean? = null,
    var shadowTLSBean: ShadowTLSBean? = null,
    var directBean: DirectBean? = null,
    var anyTLSBean: AnyTLSBean? = null,
    var shadowQUICBean: ShadowQUICBean? = null,
    var trustTunnelBean: TrustTunnelBean? = null,
    var snellBean: SnellBean? = null,
    var proxySetBean: ProxySetBean? = null,
    var chainBean: ChainBean? = null,
    var configBean: ConfigBean? = null,
) : Serializable() {

    companion object {
        const val TYPE_SOCKS = 0
        const val TYPE_HTTP = 1
        const val TYPE_SS = 2
        const val TYPE_VMESS = 4
        const val TYPE_VLESS = 5
        const val TYPE_TROJAN = 6
        const val TYPE_TROJAN_GO = 7 // Deleted
        const val TYPE_CHAIN = 8
        const val TYPE_NAIVE = 9
        const val TYPE_HYSTERIA = 15
        const val TYPE_SSH = 17
        const val TYPE_WG = 18
        const val TYPE_SHADOWTLS = 19
        const val TYPE_TUIC = 20
        const val TYPE_MIERU = 21
        const val TYPE_JUICITY = 22
        const val TYPE_DIRECT = 23
        const val TYPE_ANYTLS = 24
        const val TYPE_SHADOWQUIC = 25
        const val TYPE_PROXY_SET = 26
        const val TYPE_TRUST_TUNNEL = 27
        const val TYPE_SNELL = 28
        const val TYPE_OPENCONNECT = 29
        const val TYPE_OPENVPN = 30
        const val TYPE_MASQUE = 31
        const val TYPE_TAILSCALE = 32
        const val TYPE_TAILCAT = 33
        const val TYPE_CONFIG = 998
        const val TYPE_NEKO = 999 // Deleted

        /** Plugin not found or not support this ping type */
        const val STATUS_INVALID = -1
        const val STATUS_INITIAL = 0
        const val STATUS_AVAILABLE = 1

        /** Unclear */
        const val STATUS_UNREACHABLE = 2

        /** Has obvious error */
        const val STATUS_UNAVAILABLE = 3

        @JvmField
        val CREATOR = object : CREATOR<ProxyEntity>() {

            override fun newInstance(): ProxyEntity {
                return ProxyEntity()
            }

            override fun newArray(size: Int): Array<ProxyEntity?> {
                return arrayOfNulls(size)
            }
        }
    }

    @Ignore
    @Transient
    var dirty: Boolean = false

    override fun initializeDefaultValues() {
    }

    override fun serializeToBuffer(output: BinaryOutput) {
        output.writeInt(1)

        output.writeLong(id)
        output.writeLong(groupId)
        output.writeInt(type)
        output.writeLong(userOrder)
        output.writeLong(tx)
        output.writeLong(rx)
        output.writeInt(status)
        output.writeInt(ping)
        output.writeString(error)

        val data = BeanConverters.serialize(requireBean())
        output.writeVarInt(data.size, true)
        output.writeBytes(data)

        output.writeBoolean(dirty)
    }

    override fun deserializeFromBuffer(input: BinaryInput) {
        val version = input.readInt()

        id = input.readLong()
        groupId = input.readLong()
        type = input.readInt()
        userOrder = input.readLong()
        tx = input.readLong()
        rx = input.readLong()
        status = input.readInt()
        ping = input.readInt()
        if (version < 1) {
            // useless uuid
            input.readString()
        }
        error = input.readNullableString()
        putByteArray(input.readBytes(input.readVarInt(true)))

        dirty = input.readBoolean()
    }


    fun putByteArray(byteArray: ByteArray) {
        when (type) {
            TYPE_SOCKS -> socksBean = BeanConverters.socksDeserialize(byteArray)
            TYPE_HTTP -> httpBean = BeanConverters.httpDeserialize(byteArray)
            TYPE_SS -> ssBean = BeanConverters.shadowsocksDeserialize(byteArray)
            TYPE_SNELL -> snellBean = BeanConverters.snellDeserialize(byteArray)
            TYPE_VMESS -> vmessBean = BeanConverters.vmessDeserialize(byteArray)
            TYPE_VLESS -> vlessBean = BeanConverters.vlessDeserialize(byteArray)
            TYPE_TROJAN -> trojanBean = BeanConverters.trojanDeserialize(byteArray)
            TYPE_MIERU -> mieruBean = BeanConverters.mieruDeserialize(byteArray)
            TYPE_NAIVE -> naiveBean = BeanConverters.naiveDeserialize(byteArray)
            TYPE_HYSTERIA -> hysteriaBean = BeanConverters.hysteriaDeserialize(byteArray)
            TYPE_SSH -> sshBean = BeanConverters.sshDeserialize(byteArray)
            TYPE_WG -> wgBean = BeanConverters.wireguardDeserialize(byteArray)
            TYPE_OPENCONNECT -> openConnectBean = BeanConverters.openConnectDeserialize(byteArray)
            TYPE_OPENVPN -> openVPNBean = BeanConverters.openVPNDeserialize(byteArray)
            TYPE_MASQUE -> masqueBean = BeanConverters.masqueDeserialize(byteArray)
            TYPE_TAILSCALE -> tailscaleBean = BeanConverters.tailscaleDeserialize(byteArray)
            TYPE_TAILCAT -> tailcatBean = BeanConverters.tailcatDeserialize(byteArray)
            TYPE_TUIC -> tuicBean = BeanConverters.tuicDeserialize(byteArray)
            TYPE_JUICITY -> juicityBean = BeanConverters.juicityDeserialize(byteArray)
            TYPE_DIRECT -> directBean = BeanConverters.directDeserialize(byteArray)
            TYPE_SHADOWTLS -> shadowTLSBean = BeanConverters.shadowTLSDeserialize(byteArray)
            TYPE_ANYTLS -> anyTLSBean = BeanConverters.anyTLSDeserialize(byteArray)
            TYPE_SHADOWQUIC -> shadowQUICBean = BeanConverters.shadowQUICDeserialize(byteArray)
            TYPE_PROXY_SET -> proxySetBean = BeanConverters.proxySetDeserialize(byteArray)
            TYPE_TRUST_TUNNEL -> trustTunnelBean = BeanConverters.trustTunnelDeserialize(byteArray)
            TYPE_CHAIN -> chainBean = BeanConverters.chainDeserialize(byteArray)
            TYPE_CONFIG -> configBean = BeanConverters.configDeserialize(byteArray)
        }
    }

    fun displayName() = requireBean().displayName()
    fun displayAddress() = requireBean().displayAddress()
    fun displayNameForService(): String {
        val profileName = displayName()
        val groupName = if (DataStore.showGroupInNotification.getBlocking()) runBlocking {
            SagerDatabase.groupDao.getById(groupId).firstOrNull()?.displayName()
        } else {
            null
        }
        return if (groupName == null) profileName else "[$groupName] $profileName"
    }

    fun requireBean(): AbstractBean {
        return when (type) {
            TYPE_SOCKS -> socksBean
            TYPE_HTTP -> httpBean
            TYPE_SS -> ssBean
            TYPE_SNELL
