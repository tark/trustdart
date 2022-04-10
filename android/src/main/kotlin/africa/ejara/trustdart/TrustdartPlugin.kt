package africa.ejara.trustdart

import androidx.annotation.NonNull
import org.json.JSONObject

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

import com.google.protobuf.ByteString
import java.util.Base64

import wallet.core.jni.HDWallet
import wallet.core.jni.CoinType
import wallet.core.jni.BitcoinAddress
import wallet.core.java.AnySigner

import wallet.core.jni.BitcoinScript
import wallet.core.jni.BitcoinSigHashType
import wallet.core.jni.proto.Bitcoin
import wallet.core.jni.proto.Tron
import wallet.core.jni.proto.Bitcoin.SigningOutput
import wallet.core.jni.proto.Common.SigningError

import africa.ejara.trustdart.Numeric

/** TrustdartPlugin */
class TrustdartPlugin : FlutterPlugin, MethodCallHandler {

  init {
    System.loadLibrary("TrustWalletCore")
  }

  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel: MethodChannel

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "trustdart")
    channel.setMethodCallHandler(this)
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    when (call.method) {
      "generateMnemonic" -> {
        val passphrase: String = call.arguments()
        val wallet: HDWallet = HDWallet(128, passphrase)

        if (wallet != null) {
          result.success(wallet.mnemonic())
        } else {
          result.error(
            "generate_wallet_fail",
            "Could not generate wallet, why?", null
          )
        }
      }
      "generateMnemonicWithEntropy" -> {
        try {
          l("generateMnemonicWithEntropy")
          val entropy: ByteArray? = call.argument("entropy")
          val passphrase: String? = call.argument("passphrase")
          l("generateMnemonicWithEntropy - entropy: $entropy")
          l("generateMnemonicWithEntropy - passphrase: $passphrase")
          val wallet = HDWallet(entropy, passphrase)
          result.success(wallet.mnemonic())
        } catch (e: Exception) {
          l("generateMnemonicWithEntropy - error")
          result.error("generate_wallet_fail", "Can not generate wallet", e)
        }
      }
      "checkMnemonic" -> {
        val mnemonic: String? = call.argument("mnemonic")
        val passphrase: String? = call.argument("passphrase")
        if (mnemonic != null) {
          val wallet: HDWallet = HDWallet(mnemonic, passphrase)

          if (wallet != null) {
            result.success(true)
          } else {
            result.error(
              "no_wallet",
              "Could not generate wallet, why?", null
            )
          }
        } else {
          result.error("arguments_null", "[mnemonic] cannot be null", null)
        }
      }
      "generateAddress" -> {
        val path: String? = call.argument("path")
        val coin: String? = call.argument("coin")
        val mnemonic: String? = call.argument("mnemonic")
        val passphrase: String? = call.argument("passphrase")
        if (path != null && coin != null && mnemonic != null) {
          val wallet: HDWallet = HDWallet(mnemonic, passphrase)

          if (wallet != null) {
            val address: Map<String, String?>? = generateAddress(wallet, path, coin)
            if (address == null) result.error(
              "address_null",
              "failed to generate address",
              null
            ) else result.success(address)
          } else {
            result.error(
              "no_wallet",
              "Could not generate wallet, why?", null
            )
          }
        } else {
          result.error("arguments_null", "[path] and [coin] and [mnemonic] cannot be null", null)
        }
      }
      "validateAddress" -> {
        val address: String? = call.argument("address")
        val coin: String? = call.argument("coin")
        if (address != null && coin != null) {
          val isValid: Boolean = validateAddress(coin, address)
          result.success(isValid)
        } else {
          result.error("arguments_null", "$address and $coin cannot be null", null)
        }
      }
      "signTransaction" -> {
        val coin: String? = call.argument("coin")
        val path: String? = call.argument("path")
        val mnemonic: String? = call.argument("mnemonic")
        val passphrase: String? = call.argument("passphrase")
        val txData: Map<String, Any>? = call.argument("txData")
        if (txData != null && coin != null && path != null && mnemonic != null) {
          val wallet: HDWallet = HDWallet(mnemonic, passphrase)

          if (wallet != null) {
            val txHash: String? = signTransaction(wallet, coin, path, txData)
            if (txHash == null) result.error(
              "txhash_null",
              "failed to buid and sign transaction",
              null
            ) else result.success(txHash)
          } else {
            result.error(
              "no_wallet",
              "Could not generate wallet, why?", null
            )
          }
        } else {
          result.error(
            "arguments_null",
            "[txData], [coin] and [path] and [mnemonic] cannot be null",
            null
          )
        }
      }
      "getPublicKey" -> {
        val path: String? = call.argument("path")
        val coin: String? = call.argument("coin")
        val mnemonic: String? = call.argument("mnemonic")
        val passphrase: String? = call.argument("passphrase")
        if (path != null && coin != null && mnemonic != null) {
          val wallet: HDWallet = HDWallet(mnemonic, passphrase)

          if (wallet != null) {
            val publicKey: String? = getPublicKey(wallet, coin, path)
            if (publicKey == null) result.error(
              "address_null",
              "failed to generate address",
              null
            ) else result.success(publicKey)
          } else {
            result.error(
              "no_wallet",
              "Could not generate wallet, why?", null
            )
          }
        } else {
          result.error("arguments_null", "[path] and [coin] and [mnemonic] cannot be null", null)
        }
      }
      "getPrivateKey" -> {
        val path: String? = call.argument("path")
        val coin: String? = call.argument("coin")
        val mnemonic: String? = call.argument("mnemonic")
        val passphrase: String? = call.argument("passphrase")
        if (path != null && coin != null && mnemonic != null) {
          val wallet: HDWallet = HDWallet(mnemonic, passphrase)

          if (wallet != null) {
            val privateKey: String? = getPrivateKey(wallet, coin, path)
            if (privateKey == null) result.error(
              "address_null",
              "failed to generate address",
              null
            ) else result.success(privateKey)
          } else {
            result.error(
              "no_wallet",
              "Could not generate wallet, why?", null
            )
          }
        } else {
          result.error("arguments_null", "[path] and [coin] and [mnemonic] cannot be null", null)
        }
      }
      else -> result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  private fun generateAddress(
    wallet: HDWallet,
    path: String,
    symbol: String
  ): Map<String, String?>? {

    // special case for BTC
    // todo check if we need it for BCH as well
    if (symbol == "BTC") {
      val privateKey = wallet.getKey(CoinType.BITCOIN, path)
      val publicKey = privateKey.getPublicKeySecp256k1(true)
      val address = BitcoinAddress(publicKey, CoinType.BITCOIN.p2pkhPrefix())
      return mapOf(
        "legacy" to address.description(),
        "segwit" to CoinType.BITCOIN.deriveAddress(privateKey)
      )
    }

    val coinType = getCoinTypeFromSymbol(symbol) ?: return null
    val privateKey = wallet.getKey(coinType, path)
    return mapOf("legacy" to coinType.deriveAddress(privateKey))
  }

  private fun validateAddress(symbol: String, address: String): Boolean {
    val coinType = getCoinTypeFromSymbol(symbol) ?: return false
    return coinType.validate(address)
  }

  private fun getPublicKey(wallet: HDWallet, symbol: String, path: String): String? {
    val coinType = getCoinTypeFromSymbol(symbol) ?: return null
    val privateKey = wallet.getKey(coinType, path)
    val publicKey = privateKey.getPublicKeySecp256k1(true)
    return Base64.getEncoder().encodeToString(publicKey.data())
    // todo check why XTZ and SOL need to use getPublicKeyEd25519 instead
    // and what other coins have to use it

  }

  private fun getPrivateKey(wallet: HDWallet, symbol: String, path: String): String? {
    val coinType = getCoinTypeFromSymbol(symbol) ?: return null
    val privateKey = wallet.getKey(coinType, path)
    return Base64.getEncoder().encodeToString(privateKey.data())
  }

  private fun signTransaction(
    wallet: HDWallet,
    coin: String,
    path: String,
    txData: Map<String, Any>
  ): String? {
    return when (coin) {
      "XTZ" -> {
        signTezosTransaction(wallet, path, txData)
      }
      "ETH" -> {
        signEthereumTransaction(wallet, path, txData)
      }
      "BTC" -> {
        signBitcoinTransaction(wallet, path, txData)
      }
      "TRX" -> {
        signTronTransaction(wallet, path, txData)
      }
      "SOL" -> {
        signSolanaTransaction(wallet, path, txData)
      }
      else -> null
    }
  }

  private fun signTronTransaction(
    wallet: HDWallet,
    path: String,
    txData: Map<String, Any>
  ): String? {
    val cmd = txData["cmd"] as String
    val privateKey = wallet.getKey(CoinType.TRON, path)
    val txHash: String?
    when (cmd) {
      "TRC20" -> {
        val trc20Contract = Tron.TransferTRC20Contract.newBuilder()
          .setOwnerAddress(txData["ownerAddress"] as String)
          .setContractAddress(txData["contractAddress"] as String)
          .setToAddress(txData["toAddress"] as String)
          .setAmount(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["amount"] as String))))

        val blockHeader = Tron.BlockHeader.newBuilder()
          .setTimestamp(txData["blockTime"] as Long)
          .setTxTrieRoot(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["txTrieRoot"] as String))))
          .setParentHash(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["parentHash"] as String))))
          .setNumber((txData["number"] as Int).toLong())
          .setWitnessAddress(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["witnessAddress"] as String))))
          .setVersion(txData["version"] as Int)
          .build()

        val transaction = Tron.Transaction.newBuilder()
          .setTimestamp(txData["timestamp"] as Long)
          .setTransferTrc20Contract(trc20Contract)
          .setBlockHeader(blockHeader)
          .setFeeLimit((txData["feeLimit"] as Int).toLong())
          .build()

        val signingInput = Tron.SigningInput.newBuilder()
          .setTransaction(transaction)
          .setPrivateKey(ByteString.copyFrom(privateKey.data()))

        val output = AnySigner.sign(
          signingInput.build(),
          CoinType.TRON,
          Tron.SigningOutput.parser()
        )

        txHash = output.json
      }
      "TRC10" -> {
        val trc10Contract = Tron.TransferAssetContract.newBuilder()
          .setOwnerAddress(txData["ownerAddress"] as String)
          .setAssetName(txData["assetName"] as String)
          .setToAddress(txData["toAddress"] as String)
          .setAmount((txData["amount"] as Int).toLong())

        val blockHeader = Tron.BlockHeader.newBuilder()
          .setTimestamp(txData["blockTime"] as Long)
          .setTxTrieRoot(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["txTrieRoot"] as String))))
          .setParentHash(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["parentHash"] as String))))
          .setNumber((txData["number"] as Int).toLong())
          .setWitnessAddress(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["witnessAddress"] as String))))
          .setVersion(txData["version"] as Int)
          .build()

        val transaction = Tron.Transaction.newBuilder()
          .setTimestamp(txData["timestamp"] as Long)
          .setTransferAsset(trc10Contract)
          .setBlockHeader(blockHeader)
          .build()

        val signingInput = Tron.SigningInput.newBuilder()
          .setTransaction(transaction)
          .setPrivateKey(ByteString.copyFrom(privateKey.data()))

        val output = AnySigner.sign(
          signingInput.build(),
          CoinType.TRON,
          Tron.SigningOutput.parser()
        )
        txHash = output.json
      }
      "TRX" -> {
        val transfer = Tron.TransferContract.newBuilder()
          .setOwnerAddress(txData["ownerAddress"] as String)
          .setToAddress(txData["toAddress"] as String)
          .setAmount((txData["amount"] as Int).toLong())

        val blockHeader = Tron.BlockHeader.newBuilder()
          .setTimestamp(txData["blockTime"] as Long)
          .setTxTrieRoot(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["txTrieRoot"] as String))))
          .setParentHash(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["parentHash"] as String))))
          .setNumber((txData["number"] as Int).toLong())
          .setWitnessAddress(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["witnessAddress"] as String))))
          .setVersion(txData["version"] as Int)
          .build()

        val transaction = Tron.Transaction.newBuilder()
          .setTimestamp(txData["timestamp"] as Long)
          .setTransfer(transfer)
          .setBlockHeader(blockHeader)
          .build()

        val signingInput = Tron.SigningInput.newBuilder()
          .setTransaction(transaction)
          .setPrivateKey(ByteString.copyFrom(privateKey.data()))

        val output = AnySigner.sign(
          signingInput.build(),
          CoinType.TRON,
          Tron.SigningOutput.parser()
        )
        txHash = output.json
      }
      "FREEZE" -> {
        val freezeContract = Tron.FreezeBalanceContract.newBuilder()
          .setOwnerAddress(txData["ownerAddress"] as String)
          .setResource(txData["resource"] as String)
          .setFrozenDuration((txData["frozenDuration"] as Int).toLong())
          .setFrozenBalance((txData["frozenBalance"] as Int).toLong())

        val blockHeader = Tron.BlockHeader.newBuilder()
          .setTimestamp(txData["blockTime"] as Long)
          .setTxTrieRoot(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["txTrieRoot"] as String))))
          .setParentHash(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["parentHash"] as String))))
          .setNumber((txData["number"] as Int).toLong())
          .setWitnessAddress(ByteString.copyFrom(Numeric.hexStringToByteArray((txData["witnessAddress"] as String))))
          .setVersion(txData["version"] as Int)
          .build()

        val transaction = Tron.Transaction.newBuilder()
          .setTimestamp(txData["timestamp"] as Long)
          .setFreezeBalance(freezeContract)
          .setBlockHeader(blockHeader)
          .build()

        val signingInput = Tron.SigningInput.newBuilder()
          .setTransaction(transaction)
          .setPrivateKey(ByteString.copyFrom(privateKey.data()))

        val output = AnySigner.sign(
          signingInput.build(),
          CoinType.TRON,
          Tron.SigningOutput.parser()
        )
        txHash = output.json
      }
      "CONTRACT" -> {
        txHash = null
      }
      else -> txHash = null
    }
    return txHash
  }

  private fun signTezosTransaction(
    wallet: HDWallet,
    path: String,
    txData: Map<String, Any>
  ): String? {
    val privateKey = wallet.getKey(CoinType.TEZOS, path)
    val opJson = JSONObject(txData).toString()
    return AnySigner.signJSON(opJson, privateKey.data(), CoinType.TEZOS.value())
  }

  private fun signEthereumTransaction(
    wallet: HDWallet,
    path: String,
    txData: Map<String, Any>
  ): String? {
    val privateKey = wallet.getKey(CoinType.ETHEREUM, path)
    val opJson = JSONObject(txData).toString()
    return AnySigner.signJSON(opJson, privateKey.data(), CoinType.ETHEREUM.value())
  }

  private fun signSolanaTransaction(
    wallet: HDWallet,
    path: String,
    txData: Map<String, Any>
  ): String? {
    val privateKey = wallet.getKey(CoinType.SOLANA, path)
    val opJson = JSONObject(txData).toString()
    return AnySigner.signJSON(opJson, privateKey.data(), CoinType.SOLANA.value())
  }

  private fun signBitcoinTransaction(
    wallet: HDWallet,
    path: String,
    txData: Map<String, Any>
  ): String {
    val privateKey = wallet.getKey(CoinType.BITCOIN, path)
    val utxos: List<Map<String, Any>> = txData["utxos"] as List<Map<String, Any>>

    val input = Bitcoin.SigningInput.newBuilder()
      .setAmount((txData["amount"] as Int).toLong())
      .setHashType(BitcoinScript.hashTypeForCoin(CoinType.BITCOIN))
      .setToAddress(txData["toAddress"] as String)
      .setChangeAddress(txData["changeAddress"] as String)
      .setByteFee(1)
      .addPrivateKey(ByteString.copyFrom(privateKey.data()))

    for (utx in utxos) {
      val txHash = Numeric.hexStringToByteArray(utx["txid"] as String)
      txHash.reverse()
      val outPoint = Bitcoin.OutPoint.newBuilder()
        .setHash(ByteString.copyFrom(txHash))
        .setIndex(utx["vout"] as Int)
        .setSequence(Long.MAX_VALUE.toInt())
        .build()
      val txScript = Numeric.hexStringToByteArray(utx["script"] as String)
      val utxo = Bitcoin.UnspentTransaction.newBuilder()
        .setAmount((utx["value"] as Int).toLong())
        .setOutPoint(outPoint)
        .setScript(ByteString.copyFrom(txScript))
        .build()
      input.addUtxo(utxo)
    }

    var output = AnySigner.sign(input.build(), CoinType.BITCOIN, SigningOutput.parser())
    // since we want to set our own fee
    // but such functionality is not obvious in the trustWalletCore library
    // a hack is used for now to calculate the byteFee
    val size = output.encoded.toByteArray().size
    val fees = (txData["fees"] as Int).toLong()

    // this gives the fee per byte truncated to Long
    val byteFee = fees.div(size)

    // now we set new byte size
    if (byteFee > 1) {
      input.byteFee = byteFee
    }
    output = AnySigner.sign(input.build(), CoinType.BITCOIN, SigningOutput.parser())
    return Numeric.toHexString(output.encoded.toByteArray())
  }

  private fun l(message: String) {
    val tag = FormatUtil.pad30("TrustDart_").replace("-->", "")
    channel.invokeMethod("on_log_sent", "$tag: $message")
  }

  private fun lt(tag: String, message: String) {
    val paddedTag = FormatUtil.pad30(tag).replace("-->", "")
    channel.invokeMethod("on_log_sent", "$paddedTag: $message")
  }

  private fun getCoinTypeFromSymbol(symbol: String): CoinType? {
    return when (symbol) {
      "BTC" -> CoinType.BITCOIN
      "AE" -> CoinType.AETERNITY
      "AION" -> CoinType.AION
      "BNB" -> CoinType.BINANCE
      "BCH" -> CoinType.BITCOINCASH
      "BTG" -> CoinType.BITCOINGOLD
      "CLO" -> CoinType.CALLISTO
      "ADA" -> CoinType.CARDANO
      "ATOM" -> CoinType.COSMOS
      "DASH" -> CoinType.DASH
      "DCR" -> CoinType.DECRED
      "DGB" -> CoinType.DIGIBYTE
      "DOGE" -> CoinType.DOGECOIN
      "EOS" -> CoinType.EOS
      "ETH" -> CoinType.ETHEREUM
      "ETC" -> CoinType.ETHEREUMCLASSIC
      "FIO" -> CoinType.FIO
      "GO" -> CoinType.GOCHAIN
      "GRS" -> CoinType.GROESTLCOIN
      "ICX" -> CoinType.ICON
      "IOTX" -> CoinType.IOTEX
      "KAVA" -> CoinType.KAVA
      "KIN" -> CoinType.KIN
      "LTC" -> CoinType.LITECOIN
      "MONA" -> CoinType.MONACOIN
      "NAS" -> CoinType.NEBULAS
      "NULS" -> CoinType.NULS
      "XNO" -> CoinType.NANO
      "NEAR" -> CoinType.NEAR
      "NIM" -> CoinType.NIMIQ
      "ONT" -> CoinType.ONTOLOGY
      "POA" -> CoinType.POANETWORK
      "QTUM" -> CoinType.QTUM
      "XRP" -> CoinType.XRP
      "SOL" -> CoinType.SOLANA
      "XLM" -> CoinType.STELLAR
      "XTZ" -> CoinType.TEZOS
      "THETA" -> CoinType.THETA
      "TT" -> CoinType.THUNDERTOKEN
      "NEO" -> CoinType.NEO
      "TOMO" -> CoinType.TOMOCHAIN
      "TRX" -> CoinType.TRON
      "VET" -> CoinType.VECHAIN
      "VIA" -> CoinType.VIACOIN
      "WAN" -> CoinType.WANCHAIN
      "ZEC" -> CoinType.ZCASH
      "BUZZ" -> CoinType.ZCOIN
      "ZIL" -> CoinType.ZILLIQA
      "FLUX" -> CoinType.ZELCASH
      "RVN" -> CoinType.RAVENCOIN
      "WAVES" -> CoinType.WAVES
      "LUNA" -> CoinType.TERRA
      "ONE" -> CoinType.HARMONY
      "ALGO" -> CoinType.ALGORAND
      "KSM" -> CoinType.KUSAMA
      "DOT" -> CoinType.POLKADOT
      "FIL" -> CoinType.FILECOIN
      "EGLD" -> CoinType.ELROND
      "BAND" -> CoinType.BANDCHAIN
      "SMARTCHAINLEGACY" -> CoinType.SMARTCHAINLEGACY // ?
      "SMARTCHAIN" -> CoinType.SMARTCHAIN // ?
      "OASIS" -> CoinType.OASIS
      "MATIC" -> CoinType.POLYGON
      "RUNE" -> CoinType.THORCHAIN
      "BLZ" -> CoinType.BLUZELLE
      "OPTIMISM" -> CoinType.OPTIMISM
      "ARBITRUM" -> CoinType.ARBITRUM
      "ECOC" -> CoinType.ECOCHAIN
      "AVAX" -> CoinType.AVALANCHECCHAIN
      "XDAI" -> CoinType.XDAI
      "FTM" -> CoinType.FANTOM
      else -> null
    }

  }
}
