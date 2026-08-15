package com.next.bypass;

import android.content.Context;
import android.content.pm.PackageInfo;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.util.ArrayList;
import java.util.List;

public class HookEntry implements IXposedHookLoadPackage {

    private static final String TARGET = "com.oplus.claw";
    private static final String TAG = "BreenoNextBypass";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals(TARGET)) return;
        ClassLoader cl = lpparam.classLoader;
        XposedBridge.log(TAG + ": Loaded into " + TARGET);

        hookRootDetection(cl);
        hookRootChecker(cl);
        hookBootloaderCheck(cl);
        hookViewModelRootCheck(cl);
        hookPrecheckBypass(cl);
        hookCachedDecision(cl);
        hookHttpResponse(cl);
        hookStreamError(cl);
    }

    private void hookRootDetection(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("aq.e6", cl), "f",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(false);
                            XposedBridge.log(TAG + ": Bypassed root detection (e6.f)");
                        }
                    });
        } catch (Throwable ignored) {
            try {
                XposedHelpers.findAndHookMethod(
                        XposedHelpers.findClass("com.oplus.anim.w", cl), "e",
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                param.setResult(false);
                                XposedBridge.log(TAG + ": Bypassed root detection (anim.w.e)");
                            }
                        });
            } catch (Throwable e) {
                XposedBridge.log(TAG + ": Failed to hook root detection — " + e.getMessage());
            }
        }
    }

    private void hookRootChecker(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.k4", cl), "b",
                    String.class, boolean.class,
                    XposedHelpers.findClass("g20.a", cl),
                    XposedHelpers.findClass("y20.y", cl),
                    XposedHelpers.findClass("x10.c", cl),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(false);
                            XposedBridge.log(TAG + ": Bypassed root checker (k4.b)");
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    private void hookBootloaderCheck(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.s4", cl), "i",
                    Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(false);
                            XposedBridge.log(TAG + ": Bypassed bootloader check (s4.i)");
                        }
                    });
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Failed to hook s4.i — " + e.getMessage());
        }
    }

    private void hookViewModelRootCheck(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.m1", cl), "f",
                    String.class, XposedHelpers.findClass("x10.c", cl),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(null);
                            XposedBridge.log(TAG + ": Bypassed ViewModel root check (m1.f)");
                        }
                    });
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Failed to hook m1.f — " + e.getMessage());
        }
    }

    private void hookPrecheckBypass(ClassLoader cl) {
        try {
            final Class<?> e1 = XposedHelpers.findClass("com.oplus.claw.welcome.e1", cl);
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.m1", cl), "h",
                    boolean.class, boolean.class, String.class, boolean.class,
                    XposedHelpers.findClass("x10.c", cl),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(XposedHelpers.newInstance(e1));
                            XposedBridge.log(TAG + ": Bypassed /precheck (m1.h)");
                        }
                    });
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Failed to hook m1.h — " + e.getMessage());
        }
    }

    private void hookCachedDecision(ClassLoader cl) {
        try {
            final Class<?> h2 = XposedHelpers.findClass("com.oplus.claw.welcome.h2", cl);
            XC_MethodHook handler = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(XposedHelpers.newInstance(h2,
                            System.currentTimeMillis(), "", "", true));
                    XposedBridge.log(TAG + ": Cached decision -> Allowed");
                }
            };
            try {
                XposedHelpers.findAndHookMethod(
                        XposedHelpers.findClass("com.oplus.claw.welcome.p", cl), "b",
                        Context.class, handler);
            } catch (Throwable ignored) {
                XposedHelpers.findAndHookMethod(
                        XposedHelpers.findClass("com.oplus.claw.welcome.o", cl), "b",
                        Context.class, handler);
            }
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Failed to hook cached decision — " + e.getMessage());
        }
    }

    private void hookHttpResponse(ClassLoader cl) {
        try {
            final Class<?> e4 = XposedHelpers.findClass("com.oplus.claw.welcome.e4", cl);
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.u2", cl), "e",
                    e4, String.class, String.class, boolean.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object resp = param.args[0];
                            Object msgObj = XposedHelpers.getObjectField(resp, "b");
                            if (!(msgObj instanceof String)) return;
                            String msg = (String) msgObj;
                            if (msg.contains("-12002") || msg.contains("-12003")) {
                                XposedHelpers.setObjectField(resp, "b", "{\"code\":0,\"message\":\"ok\"}");
                                XposedHelpers.setIntField(resp, "a", 200);
                                XposedHelpers.setBooleanField(resp, "c", true);
                                XposedBridge.log(TAG + ": Stripped -12002/-12003 from HTTP response (u2.e)");
                            }
                        }
                    });
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Failed to hook u2.e — " + e.getMessage());
        }
    }

    private void hookStreamError(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("si.f0", cl), "b",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object result = param.getResult();
                            if (result == null) return;
                            Object codeObj = XposedHelpers.getObjectField(result, "c");
                            if ("-12002".equals(codeObj) || "-12003".equals(codeObj)) {
                                param.setResult(null);
                                XposedBridge.log(TAG + ": Suppressed -12002/-12003 stream error (f0.b)");
                            }
                        }
                    });
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Failed to hook si.f0.b — " + e.getMessage());
        }
    }
}
