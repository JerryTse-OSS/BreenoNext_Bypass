package com.next.bypass;

import android.content.Context;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicReference;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookEntry implements IXposedHookLoadPackage {

    private static final String TARGET = "com.oplus.claw";
    private static final String TAG = "BreenoNextBypass";

    private ClassLoader cl;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals(TARGET)) return;
        cl = lpparam.classLoader;
        XposedBridge.log(TAG + ": Loaded into " + TARGET);

        hookAccessGate();
        hookN2PolicyState();
        hookRootDetection();
        hookBetaVerification();
        hookBootloaderCheck();
        hookViewModelRootCheck();
        hookPrecheckBypass();
        hookCachedDecision();
    }

    // ==================== Access Gate Bypass ====================

    private void hookAccessGate() {
        boolean dHooked = tryHook("com.oplus.claw.welcome.k3", "d",
                String.class, XC_MethodReplacement.DO_NOTHING);
        XposedBridge.log(TAG + ": hookAccessGate k3.d(String) — " + (dHooked ? "OK" : "FAILED"));

        try {
            final Class<?> h2Class = XposedHelpers.findClass("com.oplus.claw.welcome.h2", cl);
            Object inMemoryGranted = findStaticField("com.oplus.claw.welcome.i2", "a");
            if (inMemoryGranted == null) inMemoryGranted = findStaticField("com.oplus.claw.welcome.i2", "f15306a");
            if (inMemoryGranted != null) {
                final Object src = inMemoryGranted;
                boolean fHooked = tryHook("com.oplus.claw.welcome.k3", "f",
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                param.setResult(XposedHelpers.newInstance(h2Class,
                                        src, Long.valueOf(System.currentTimeMillis())));
                            }
                        });
                XposedBridge.log(TAG + ": hookAccessGate k3.f() → Allowed — " + (fHooked ? "OK" : "FAILED"));
            } else {
                XposedBridge.log(TAG + ": hookAccessGate i2.a not found");
            }
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookAccessGate k3.f() error — " + e.getMessage());
        }
    }

    // ==================== N2 Policy State Bypass ====================

    private void hookN2PolicyState() {
        try {
            Object n2RefObj = findStaticField("com.oplus.claw.welcome.n2", "b");
            if (n2RefObj == null) n2RefObj = findStaticField("com.oplus.claw.welcome.n2", "f15415b");
            if (n2RefObj == null) {
                XposedBridge.log(TAG + ": hookN2PolicyState — n2.b not found");
                return;
            }
            final Object n2Ref = n2RefObj;
            final Class<?> k2Class = findClass("com.oplus.claw.welcome.k2");
            Object pendingObj = XposedHelpers.getStaticObjectField(k2Class, "a");
            if (pendingObj == null) pendingObj = XposedHelpers.getStaticObjectField(k2Class, "f15329a");
            final Object pending = pendingObj;
            Method setMethod = AtomicReference.class.getDeclaredMethod("set", Object.class);
            XposedBridge.hookMethod(setMethod, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.thisObject != n2Ref) return;
                    Object l2Obj = param.args[0];
                    if (l2Obj == null) return;
                    boolean enforced = getBoolField(l2Obj, "a", "f15357a");
                    Object verdict = getObjField(l2Obj, "c", "f15359c");
                    if (enforced && verdict == pending) {
                        param.setResult(null);
                        XposedBridge.log(TAG + ": Blocked n2 policy → enforced+pending");
                    }
                }
            });
            XposedBridge.log(TAG + ": hookN2PolicyState — OK");
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookN2PolicyState error — " + e.getMessage());
        }
    }

    // ==================== Root Detection Bypass ====================

    private void hookRootDetection() {
        XC_MethodHook hook = setResultHook(false);
        if (tryHook("ap.b", "g", hook)) return;
        if (tryHook("aq.e6", "f", hook)) return;
        tryHook("com.oplus.anim.w", "e", hook);
    }

    // ==================== Beta Verify Bypass ====================

    private void hookBetaVerification() {
        XC_MethodHook hook = setResultHook(false);
        // 170069
        if (tryHookParams("com.oplus.claw.welcome.n2", "b",
                String.class, Boolean.class,
                findClass("n20.a"), findClass("f30.x"), findClass("e20.c"), hook)) return;
        // 170068 / 170066
        tryHookParams("com.oplus.claw.welcome.k4", "b",
                String.class, boolean.class,
                findClass("g20.a"), findClass("y20.y"), findClass("x10.c"), hook);
    }

    // ==================== Bootloader Bypass ====================

    private void hookBootloaderCheck() {
        XC_MethodHook hook = setResultHook(false);
        if (tryHook("com.oplus.claw.welcome.w4", "i", Context.class, hook)) return;
        if (tryHook("com.oplus.claw.welcome.s4", "i", Context.class, hook)) return;
        tryHook("com.oplus.anim.w", "e", hook);
    }

    // ==================== ViewModel root Bypass ====================

    private void hookViewModelRootCheck() {
        XC_MethodHook hook = setResultHook((Object) null);
        if (tryHookParams("com.oplus.claw.welcome.n1", "f",
                String.class, findClass("e20.c"), hook)) return;
        tryHookParams("com.oplus.claw.welcome.m1", "f",
                String.class, findClass("x10.c"), hook);
    }

    // ==================== /precheck Bypass ====================

    private void hookPrecheckBypass() {
        Object e1 = findStaticField("com.oplus.claw.welcome.e1", "f15227a");
        if (e1 == null) e1 = findStaticField("com.oplus.claw.welcome.e1", "a");
        if (e1 == null) {
            XposedBridge.log(TAG + ": hookPrecheckBypass — e1 not found");
            return;
        }
        final Object idle = e1;
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                param.setResult(idle);
            }
        };
        if (tryHookParams("com.oplus.claw.welcome.n1", "h",
                boolean.class, boolean.class, String.class, boolean.class,
                findClass("e20.c"), hook)) return;
        tryHookParams("com.oplus.claw.welcome.m1", "h",
                boolean.class, boolean.class, String.class, boolean.class,
                findClass("x10.c"), hook);
    }

    // ==================== Cached Decision Bypass ====================

    private void hookCachedDecision() {
        try {
            final Class<?> o2Class = XposedHelpers.findClass("com.oplus.claw.welcome.o2", cl);
            XC_MethodHook hook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(XposedHelpers.newInstance(o2Class,
                            System.currentTimeMillis(), "", "", true));
                }
            };
            if (tryHook("com.oplus.claw.welcome.p", "b", Context.class, hook)) return;
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookCachedDecision 170069 error — " + e.getMessage());
        }
        try {
            final Class<?> h2Old = XposedHelpers.findClass("com.oplus.claw.welcome.h2", cl);
            XC_MethodHook hook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(XposedHelpers.newInstance(h2Old,
                            System.currentTimeMillis(), "", "", true));
                }
            };
            if (tryHook("com.oplus.claw.welcome.p", "b", Context.class, hook)) return;
            if (tryHook("com.oplus.claw.welcome.o", "b", Context.class, hook)) return;
        } catch (Throwable ignored) {
        }
        XposedBridge.log(TAG + ": hookCachedDecision — all attempts failed");
    }

    // ==================== Misc for Hook ====================

    private boolean tryHook(String className, String methodName, XC_MethodHook hook) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, hook);
            XposedBridge.log(TAG + ": Hooked " + className + "." + methodName);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean tryHook(String className, String methodName,
                            Class<?> p1, XC_MethodHook hook) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, p1, hook);
            XposedBridge.log(TAG + ": Hooked " + className + "." + methodName);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean tryHookParams(String className, String methodName,
                                  Object... paramTypesAndCallback) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, paramTypesAndCallback);
            XposedBridge.log(TAG + ": Hooked " + className + "." + methodName);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private Class<?> findClass(String name) {
        return XposedHelpers.findClass(name, cl);
    }

    private Object findStaticField(String className, String fieldName) {
        try {
            return XposedHelpers.getStaticObjectField(findClass(className), fieldName);
        } catch (Throwable e) {
            return null;
        }
    }

    private static boolean getBoolField(Object obj, String name1, String name2) {
        try { return XposedHelpers.getBooleanField(obj, name1); }
        catch (Throwable ignored) {}
        try { return XposedHelpers.getBooleanField(obj, name2); }
        catch (Throwable ignored) { return false; }
    }

    private static Object getObjField(Object obj, String name1, String name2) {
        try { return XposedHelpers.getObjectField(obj, name1); }
        catch (Throwable ignored) {}
        try { return XposedHelpers.getObjectField(obj, name2); }
        catch (Throwable ignored) { return null; }
    }

    private static XC_MethodHook setResultHook(final Object value) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                param.setResult(value);
            }
        };
    }
}
