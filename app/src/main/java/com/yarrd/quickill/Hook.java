package com.yarrd.quickill;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Map;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 强制快手 Aegon 网络层关闭 QUIC，并让快手网关回落 TCP。
 *
 * 目标全部在 14.10.30.51353 上验证存在：
 *   com.kuaishou.aegon.Aegon#nativeSetGlobalConfig(String jsonConfig, String storagePath, boolean)
 *   com.kuaishou.aegon.Aegon#nativeSetQuicFallbackToTcpBlacklist(String[] hosts)
 *   com.kuaishou.aegon.Aegon#k(Map)               ← Java 层配置入口
 *
 * 旧模块 hook 的 nativeUpdateConfig 在该版本不存在，所以一直没生效。
 */
public class Hook implements IXposedHookLoadPackage {

    private static final String TAG = "QUICK";
    private static final String PKG = "com.smile.gifmaker";
    private static final String AEGON = "com.kuaishou.aegon.Aegon";

    /** 这些 host 强制走 TCP（不试 QUIC） */
    private static final String[] TCP_ONLY_HOSTS = {
            "ksapisrv.com",
            "az1-api.ksapisrv.com",
            "az2-api.ksapisrv.com",
            "az3-api.ksapisrv.com",
            "az4-api.ksapisrv.com",
            "apissl.ksapisrv.com",
            "apinew.ksapisrv.com",
    };

    /** 往配置 JSON 里注入：关 QUIC + 把网关加进 quic 黑名单 */
    private static String patchConfig(String json) {
        if (json == null) json = "{}";
        try {
            JSONObject o = new JSONObject(json);
            o.put("enable_quic", false);

            JSONArray bl = o.optJSONArray("quic_host_blacklist");
            if (bl == null) bl = new JSONArray();
            for (String h : TCP_ONLY_HOSTS) bl.put("." + h);
            o.put("quic_host_blacklist", bl);

            o.put("altsvc_broken_time_max", 86400);
            o.put("altsvc_broken_time_base", 86400);
            String out = o.toString();
            Log.i(TAG, "config patched, len " + json.length() + " -> " + out.length());
            return out;
        } catch (Throwable t) {
            Log.e(TAG, "patchConfig failed, pass original: " + t);
            return json;
        }
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!PKG.equals(lpparam.packageName)) return;
        Log.i(TAG, "loaded into " + PKG);
        try { Cap.install(lpparam.classLoader); } catch (Throwable t) { Log.e(TAG, "Cap.install failed: " + t); }

        Class<?> aegon;
        try {
            aegon = XposedHelpers.findClass(AEGON, lpparam.classLoader);
        } catch (Throwable t) {
            Log.e(TAG, "Aegon class not found: " + t);
            return;
        }

        // ① 原生配置入口：初始化时传的 JSON 就是它
        try {
            XposedHelpers.findAndHookMethod(aegon, "nativeSetGlobalConfig",
                    String.class, String.class, boolean.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String cfg = (String) param.args[0];
                            param.args[0] = patchConfig(cfg);
                            Log.i(TAG, "nativeSetGlobalConfig hooked, enable_quic -> false");
                        }
                    });
            Log.i(TAG, "hook nativeSetGlobalConfig ok");
        } catch (Throwable t) {
            Log.e(TAG, "hook nativeSetGlobalConfig failed: " + t);
        }

        // ② Java 层配置 Map 入口 Aegon.k(Map)，key 0 是配置 JSON
        try {
            XposedHelpers.findAndHookMethod(aegon, "k", Map.class, new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void beforeHookedMethod(MethodHookParam param) {
                    Map<Object, Object> m = (Map<Object, Object>) param.args[0];
                    if (m == null) return;
                    Object v = m.get(0);
                    if (v instanceof String) m.put(0, patchConfig((String) v));
                    Log.i(TAG, "Aegon.k(Map) hooked");
                }
            });
            Log.i(TAG, "hook Aegon.k ok");
        } catch (Throwable t) {
            Log.e(TAG, "hook Aegon.k failed (non fatal): " + t);
        }
    }
}
