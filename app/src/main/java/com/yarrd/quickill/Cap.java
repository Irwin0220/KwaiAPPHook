package com.yarrd.quickill;

import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 最小化抓包 —— 只挂框架层，不做任何类加载拦截。
 *
 * 目标：抓到运营商 SDK（com.unicom.online.account.kernel）发出的请求。
 * SDK 的网络走蜂窝绑定，okhttp hook 看不见，但 java.net.URL 是框架层，绕不过。
 *
 * 刻意不做的事：
 *   ✗ 全局 hook ClassLoader.loadClass  —— 会导致 App 卡死在运营商登录页（已实测）
 *   ✗ hook WebView 相关              —— 对运营商授权链路无帮助
 */
public final class Cap {

    private static final String TAG = "QUICKCAP";
    private static final File OUT = new File("/data/local/tmp/quickcap.log");

    public static synchronized void w(String s) {
        Log.i(TAG, s);
        try (FileWriter fw = new FileWriter(OUT, true)) { fw.write(s); fw.write("\n"); } catch (Throwable ignored) {}
    }

    public static void install(ClassLoader cl) {
        w("=== Cap(minimal) installed ===");

        // ① 框架层：所有 URLConnection 都从 URL.openConnection 走
        try {
            Class<?> u = URL.class;
            XposedBridge.hookAllMethods(u, "openConnection", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        w("[URL] " + String.valueOf(p.thisObject));
                    } catch (Throwable ignored) {}
                }
            });
            w("hook URL.openConnection ok");
        } catch (Throwable t) { w("hook URL.openConnection failed: " + t); }

        // ② 请求头
        try {
            Class<?> h = java.net.HttpURLConnection.class;
            XposedBridge.hookAllMethods(h, "setRequestProperty", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        String k = String.valueOf(p.args[0]), v = String.valueOf(p.args[1]);
                        if (!k.equalsIgnoreCase("Content-Type") && !k.equalsIgnoreCase("Content-Length")
                                && !k.equalsIgnoreCase("Host") && !k.equalsIgnoreCase("Accept-Encoding"))
                            w("      H " + k + ": " + v);
                    } catch (Throwable ignored) {}
                }
            });
            XposedBridge.hookAllMethods(h, "getResponseCode", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try { w("      RC " + p.getResult()); } catch (Throwable ignored) {}
                }
            });
            w("hook HttpURLConnection ok");
        } catch (Throwable t) { w("hook HttpURLConnection failed: " + t); }

        // ③ okhttp（App 自己的 API 请求，主要看 POST body）
        try {
            Class<?> b = XposedHelpers.findClass("okhttp3.Request$Builder", cl);
            XposedBridge.hookAllMethods(b, "build", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Object req = p.getResult();
                        String u = String.valueOf(XposedHelpers.callMethod(req, "url"));
                        w("[OKREQ] " + u);
                        Object body = XposedHelpers.callMethod(req, "body");
                        if (body != null) {
                            Object s = body.toString();
                            w("      B " + s);
                        }
                    } catch (Throwable ignored) {}
                }
            });
            w("hook okhttp build ok");
        } catch (Throwable t) { w("hook okhttp failed: " + t); }


        // ⑤ 运营商 SDK（in DVA plugin dex）—— 抓 token 产出点
        try {
            Class<?> dcl = XposedHelpers.findClass("dalvik.system.DexClassLoader", cl);
            XposedBridge.hookAllConstructors(dcl, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try { hookSdk((ClassLoader) p.thisObject); } catch (Throwable ignored) {}
                }
            });
            w("hook DexClassLoader ctor ok");
        } catch (Throwable t) { w("hook DexClassLoader failed: " + t); }
        // 插件可能已经加载过，用已知 loader 再试一次
        try {
            for (java.lang.ClassLoader l : new java.lang.ClassLoader[]{
                    XposedHelpers.findClass("okhttp3.OkHttpClient", cl).getClassLoader()}) {
                hookSdk(l);
            }
        } catch (Throwable ignored) {}

        // ④ Cronet（App 部分请求走这里，比如 mobileQuick）
        try {
            Class<?> c = XposedHelpers.findClass("aegon.chrome.net.impl.CronetUrlRequest", cl);
            XposedBridge.hookAllMethods(c, "start", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        Object v = XposedHelpers.getObjectField(p.thisObject, "l");
                        w("[CRONET] " + String.valueOf(v));
                    } catch (Throwable ignored) {}
                }
            });
            w("hook Cronet.start ok");
        } catch (Throwable t) { w("hook Cronet failed: " + t); }
    }

    private static final java.util.Set<String> SDK_HOOKED = java.util.Collections.synchronizedSet(new java.util.HashSet<String>());

    /** hook 运营商 SDK 的 token 解析器 */
    private static void hookSdk(final ClassLoader loader) {
        if (loader == null) return;
        if (!SDK_HOOKED.add(String.valueOf(System.identityHashCode(loader)))) return;
        for (String name : new String[]{"i21.c_f", "com.unicom.online.account.kernel.AuthModel"}) {
            try {
                Class<?> c = XposedHelpers.findClass(name, loader);
                w(">>> SDK class found: " + name + " in " + loader);
                for (String m : new String[]{"u", "x"}) {
                    try {
                        XposedBridge.hookAllMethods(c, m, new XC_MethodHook() {
                            @Override protected void beforeHookedMethod(MethodHookParam q) {
                                try {
                                    for (Object a : q.args) {
                                        if (a instanceof String && ((String) a).length() > 40) {
                                            w("[SDK-RESP:" + mhash(q) + "] " + a);
                                        }
                                    }
                                } catch (Throwable ignored) {}
                            }
                        });
                        w("   hook " + name + "." + m + " ok");
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
        }
        // AuthModel 字段全量 dump
        try {
            Class<?> am = XposedHelpers.findClass("com.unicom.online.account.kernel.AuthModel", loader);
            XposedBridge.hookAllMethods(am, "toString", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam q) {
                    try { w("[AUTHMODEL] " + q.getResult()); } catch (Throwable ignored) {}
                }
            });
            w("   hook AuthModel.toString ok");
        } catch (Throwable ignored) {}
    }

    private static String mhash(XC_MethodHook.MethodHookParam q) {
        return String.valueOf(q.method != null ? ((java.lang.reflect.Method) q.method).getName() : "?");
    }

}
