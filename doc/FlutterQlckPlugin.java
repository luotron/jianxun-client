package com.qlck.plugin.flutter_qlck;

import android.os.Build;
import com.cf.msc.sdk.AppVest;
import com.cf.msc.sdk.SecurityConnection;
import com.tekartik.sqflite.Constant;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.StandardMethodCodec;
import java.util.Objects;
import org.apache.tika.metadata.TikaCoreProperties;
import org.apache.tika.parser.external.ExternalParsersConfigReaderMetKeys;
import tv.danmaku.ijk.media.player.IjkMediaPlayer;

/* JADX INFO: loaded from: classes3.dex */
public class FlutterQlckPlugin implements FlutterPlugin, MethodChannel.MethodCallHandler {
    private MethodChannel channel;

    @Override // io.flutter.embedding.engine.plugins.FlutterPlugin
    public void onAttachedToEngine(FlutterPlugin.FlutterPluginBinding flutterPluginBinding) {
        BinaryMessenger binaryMessenger = flutterPluginBinding.getBinaryMessenger();
        MethodChannel methodChannel = new MethodChannel(binaryMessenger, "flutter_qlck", StandardMethodCodec.INSTANCE, binaryMessenger.makeBackgroundTaskQueue());
        this.channel = methodChannel;
        methodChannel.setMethodCallHandler(this);
    }

    @Override // io.flutter.plugin.common.MethodChannel.MethodCallHandler
    public void onMethodCall(MethodCall methodCall, MethodChannel.Result result) {
        if (methodCall.method.equals(Constant.METHOD_GET_PLATFORM_VERSION)) {
            result.success("Android " + Build.VERSION.RELEASE);
            return;
        }
        if (methodCall.method.equals("initQLCK")) {
            result.success(Boolean.valueOf(AppVest.init((String) methodCall.argument(ExternalParsersConfigReaderMetKeys.METADATA_KEY_ATTR), (String) methodCall.argument("uuid")) == 0));
            return;
        }
        if (methodCall.method.equals("getServerIPAndPort")) {
            SecurityConnection serverIPAndPort = AppVest.getServerIPAndPort((String) methodCall.argument("host"), Integer.parseInt((String) Objects.requireNonNull((String) methodCall.argument(IjkMediaPlayer.OnNativeInvokeListener.ARG_PORT))));
            if (serverIPAndPort == null || serverIPAndPort.getServerPort().intValue() <= 0 || serverIPAndPort.getServerPort().intValue() > 65535 || serverIPAndPort.getServerIp() == null || serverIPAndPort.getServerIp().isEmpty()) {
                result.success("");
                return;
            } else {
                result.success(serverIPAndPort.getServerIp() + TikaCoreProperties.NAMESPACE_PREFIX_DELIMITER + serverIPAndPort.getServerPort());
                return;
            }
        }
        result.notImplemented();
    }

    @Override // io.flutter.embedding.engine.plugins.FlutterPlugin
    public void onDetachedFromEngine(FlutterPlugin.FlutterPluginBinding flutterPluginBinding) {
        this.channel.setMethodCallHandler(null);
    }
}
