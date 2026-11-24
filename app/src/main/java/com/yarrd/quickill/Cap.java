package com.yarrd.quickill;

import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.WeakHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 进程内抓包：okhttp + Cronet，覆盖插件独立 ClassLoader。
 *
 * 关键点：登录插件（login_gateway_plugin）跑在自己的 ClassLoader 里，
 * 用主 ClassLoader 找 aegon.chrome.net.impl.CronetUrlRequest 找到的是另一份。
 * 这里 hook 全局 ClassLoader.loadClass，目标类一被加载就在它真正的 ClassLoader 上挂 hook。
 */
public final class Cap {

    private static final String TAG = "QUICKCAP";
    private static final File OUT = new File("/data/local/tmp/quickcap.log");

    private static final Set<String> HOOKED = Collections.synchronizedSet(new HashSet<String>());

    public static synchronized void w(String s) {
        Log.i(TAG, s);
        try (FileWriter fw = new FileWriter(OUT, true)) { fw.write(s); fw.write("\n"); } catch (Throwable ignored) {}
    }

    private static final String[] CRONET_CLASSES = {
            "aegon.chrome.net.impl.CronetUrlRequest",
            "org.chromium.net.impl.CronetUrlRequest",
            "com.kuaishou.aegon.net.impl.CronetUrlRequest",
    };

    public static void install(final ClassLoader mainCl) {
        w("=== Cap installed, cl=" + mainCl + " ===");
        hookOkhttp(mainCl);

        // 全局：任何 ClassLoader 加载到目标类时立刻挂 hook
        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    Object r = p.getResult();
                    if (r == null) return;
                    String n = ((Class<?>) r).getName();
                    for (String t : CRONET_CLASSES) {
                        if (t.equals(n)) { hookCronet((Class<?>) r); }
                    }
                    if ("qhm.a".equals(n) || "xfm.a".equals(n)) { hookLoginApi((Class<?>) r); }
                    if ("okhttp3.Request$Builder".equals(n)) {
                        hookOkhttp(((Class<?>) r).getClassLoader());
                    }
                }
            });
            w("hook ClassLoader.loadClass ok");
        } catch (Throwable t) { w("hook loadClass failed: " + t); }

        // 已经加载过的，直接试一遍
        for (String t : CRONET_CLASSES) {
            try { hookCronet(XposedHelpers.findClass(t, mainCl)); } catch (Throwable ignored) {}
        }
        for (String t : new String[]{"qhm.a", "xfm.a"}) {
            try { hookLoginApi(XposedHelpers.findClass(t, mainCl)); } catch (Throwable ignored) {}
        }
    }

    // ---------------- okhttp ----------------
    private static void hookOkhttp(ClassLoader cl) {
        try {
            Class<?> b = XposedHelpers.findClass("okhttp3.Request$Builder", cl);
            XposedBridge.hookAllMethods(b, "build", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Object req = p.getResult();
                        String u = String.valueOf(XposedHelpers.callMethod(req, "url"));
                        String h = String.valueOf(XposedHelpers.callMethod(req, "headers")).replace('\n', '|');
                        Object body = XposedHelpers.callMethod(req, "body");
                        w("[REQ] " + u);
                        w("      H " + h);
                        if (body != null) w("      B " + body);
                    } catch (Throwable t) { w("[REQ-ERR] " + t); }
                }
            });
            w("hook okhttp build ok");
        } catch (Throwable t) { w("hook okhttp failed: " + t); }

        try {
            Class<?> chain = XposedHelpers.findClass("okhttp3.internal.http.RealInterceptorChain", cl);
            XposedBridge.hookAllMethods(chain, "proceed", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Object resp = p.getResult();
                        if (resp == null) return;
                        Object req = XposedHelpers.callMethod(resp, "request");
                        String u = String.valueOf(XposedHelpers.callMethod(req, "url"));
                        int code = (Integer) XposedHelpers.callMethod(resp, "code");
                        Object peek = XposedHelpers.callMethod(resp, "peekBody", 8000L);
                        w("[RESP " + code + "] " + u);
                        w("      R " + XposedHelpers.callMethod(peek, "string"));
                    } catch (Throwable ignored) {}
                }
            });
            w("hook proceed ok");
        } catch (Throwable t) { w("hook proceed failed: " + t); }
    }

    // ---------------- Cronet ----------------
    private static void hookCronet(Class<?> c) {
        if (c == null || !HOOKED.add(c.getName() + "@" + System.identityHashCode(c.getClassLoader()))) return;
        w(">>> hooking Cronet in loader " + c.getClassLoader() + " : " + c.getName());
        try {
            XposedBridge.hookAllMethods(c, "start", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    String u = "";
                    for (String f : new String[]{"l", "mUrl", "url"}) {
                        try { Object v = XposedHelpers.getObjectField(p.thisObject, f); if (v != null) { u = String.valueOf(v); break; } } catch (Throwable ignored) {}
                    }
                    w("[CRONET-REQ] " + u);
                    for (String f : new String[]{"q", "mRequestHeaders", "headers"}) {
                        try { Object v = XposedHelpers.getObjectField(p.thisObject, f); if (v != null) { w("      H " + String.valueOf(v).replace('\n','|')); break; } } catch (Throwable ignored) {}
                    }
                }
            });
            w("   hook Cronet.start ok");
        } catch (Throwable t) { w("   hook Cronet.start failed: " + t); }

        try {
            XposedBridge.hookAllMethods(c, "onResponseStarted", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        StringBuilder sb = new StringBuilder("[CRONET-RESP] ");
                        for (Object a : p.args) {
                            if (a instanceof String[]) { sb.append(java.util.Arrays.toString((String[]) a)); }
                            else sb.append(String.valueOf(a));
                            sb.append(" | ");
                        }
                        w(sb.toString());
                        // 从请求对象里挖 URL / headers
                        Class<?> oc = p.thisObject.getClass();
                        while (oc != null && oc != Object.class) {
                            for (java.lang.reflect.Field f : oc.getDeclaredFields()) {
                                try {
                                    f.setAccessible(true);
                                    Object v = f.get(p.thisObject);
                                    if (v == null) continue;
                                    String t = v.getClass().getName();
                                    if (t.contains("String")) { w("      F " + f.getName() + " = " + v); }
                                    else if (t.contains("Headers") || t.contains("Map")) { w("      F " + f.getName() + " = " + String.valueOf(v).replace('\n','|')); }
                                } catch (Throwable ignored) {}
                            }
                            oc = oc.getSuperclass();
                        }
                    } catch (Throwable ignored) {}
                }
            });
            w("   hook Cronet.onResponseStarted ok");
        } catch (Throwable t) { w("   hook Cronet.onResponseStarted failed: " + t); }

        try {
            XposedBridge.hookAllMethods(XposedHelpers.findClass("aegon.chrome.net.impl.CronetUploadDataStream", c.getClassLoader()),
                    "readData", new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam p) {
                            w("[CRONET-BODY?] readData args=" + p.args.length);
                        }
                    });
            w("   hook CronetUploadDataStream ok");
        } catch (Throwable ignored) {}
    }

    // ---------------- 登录 API 接口（Retrofit 实现类） ----------------
    private static void hookLoginApi(Class<?> apiIf) {
        if (apiIf == null || !HOOKED.add("api@" + System.identityHashCode(apiIf.getClassLoader()))) return;
        w(">>> hooking login api interface " + apiIf.getName());
        try {
            // 接口方法是抽象的，改挂它的代理实现：Retrofit create 出来的类
            Class<?> retrofit = XposedHelpers.findClass("retrofit2.Retrofit", apiIf.getClassLoader());
            XposedBridge.hookAllMethods(retrofit, "create", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    Object r = p.getResult();
                    if (r == null) return;
                    Class<?> rc = r.getClass();
                    if (!HOOKED.add("impl@" + rc.getName())) return;
                    w("   retrofit impl: " + rc.getName() + " for " + p.args[0]);
                    XposedBridge.hookAllMethods(rc, "invoke", new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam q) {
                            try {
                                Object m = q.args.length > 2 ? q.args[2] : null;
                                String mn = m != null ? String.valueOf(((java.lang.reflect.Method) m).getName()) : "?";
                                w("[API-CALL] method=" + mn + " args=" + (q.args.length > 1 ? String.valueOf(q.args[1]) : ""));
                            } catch (Throwable ignored) {}
                        }
                    });
                }
            });
            w("   hook retrofit2.Retrofit.create ok");
        } catch (Throwable t) { w("   hook retrofit failed: " + t); }
    }
}
