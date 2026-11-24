package com.yarrd.quickill;

import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 在快手进程内直接读取请求与响应，不依赖 MITM、不受证书固定影响。
 * 输出 /sdcard/quickcap.log（adb pull 即可，无需 root）
 */
public final class Cap {

    private static final String TAG = "QUICKCAP";
    private static final File OUT = new File("/sdcard/quickcap.log");

    public static synchronized void w(String s) {
        Log.i(TAG, s);
        try (FileWriter fw = new FileWriter(OUT, true)) {
            fw.write(s);
            fw.write("\n");
        } catch (Throwable ignored) {}
    }

    public static void install(ClassLoader cl) {
        w("=== Cap installed ===");

        // ① okhttp：每个请求构建完成时（URL + 全部 header + body）
        try {
            Class<?> b = XposedHelpers.findClass("okhttp3.Request$Builder", cl);
            XposedBridge.hookAllMethods(b, "build", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Object req = p.getResult();
                        Object url = XposedHelpers.callMethod(req, "url");
                        Object hdrs = XposedHelpers.callMethod(req, "headers");
                        Object body = XposedHelpers.callMethod(req, "body");
                        String u = String.valueOf(url);
                        w("[REQ] " + u);
                        w("      H " + String.valueOf(hdrs).replace('\n', '|'));
                        if (body != null) w("      B " + safeBody(body));
                        if (u.contains("login") || u.contains("mobileQuick") || u.contains("10010") || u.contains("wosms")) {
                            w("      ^^^ 登录相关 ^^^");
                        }
                    } catch (Throwable t) { w("[REQ-ERR] " + t); }
                }
            });
            w("hook okhttp Request$Builder.build ok");
        } catch (Throwable t) { w("hook okhttp failed: " + t); }

        // ② okhttp：响应（code + body 预览）
        try {
            Class<?> chain = XposedHelpers.findClass("okhttp3.internal.http.RealInterceptorChain", cl);
            XposedBridge.hookAllMethods(chain, "proceed", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Object resp = p.getResult();
                        if (resp == null) return;
                        Object req = XposedHelpers.callMethod(resp, "request");
                        Object url = XposedHelpers.callMethod(req, "url");
                        String u = String.valueOf(url);
                        if (!(u.contains("login") || u.contains("ksapisrv"))) return;
                        int code = (Integer) XposedHelpers.callMethod(resp, "code");
                        Object peek = XposedHelpers.callMethod(resp, "peekBody", 8000L);
                        Object s = XposedHelpers.callMethod(peek, "string");
                        w("[RESP " + code + "] " + u);
                        w("      R " + s);
                    } catch (Throwable t) { w("[RESP-ERR] " + t); }
                }
            });
            w("hook okhttp RealInterceptorChain.proceed ok");
        } catch (Throwable t) { w("hook proceed failed: " + t); }

        // ③ mobileQuick 的 Map 参数（最直接）
        try {
            Class<?> api = XposedHelpers.findClass("qhm.a", cl);
            XposedBridge.hookAllMethods(api, "g", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    w("[MQ-PARAMS] " + String.valueOf(p.args[0]));
                }
            });
            w("hook qhm.a.g(mobileQuick) ok");
        } catch (Throwable t) { w("hook qhm.a.g failed: " + t); }

        // ④ Cronet 路径
        try {
            Class<?> c = XposedHelpers.findClass("aegon.chrome.net.impl.CronetUrlRequest", cl);
            XposedBridge.hookAllMethods(c, "start", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        Object u = XposedHelpers.getObjectField(p.thisObject, "l");
                        String s = String.valueOf(u);
                        w("[CRONET-REQ] " + s);
                        Object h = XposedHelpers.getObjectField(p.thisObject, "q");
                        if (h != null) w("      H " + String.valueOf(h).replace('\n', '|'));
                    } catch (Throwable t) { w("[CRONET-ERR] " + t); }
                }
            });
            w("hook CronetUrlRequest.start ok");
        } catch (Throwable t) { w("hook cronet failed: " + t); }
    }

    private static String safeBody(Object body) {
        try {
            Object s = body.toString();
            if (s != null && !s.contains("RequestBody$") ) return String.valueOf(s);
        } catch (Throwable ignored) {}
        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            Object buf = XposedHelpers.newInstance(XposedHelpers.findClass("okio.Buffer", null));
            XposedHelpers.callMethod(body, "writeTo", buf);
            Object bytes = XposedHelpers.callMethod(buf, "readByteArray");
            return new String((byte[]) bytes, "UTF-8");
        } catch (Throwable t) { return "<body unreadable>"; }
    }
}
