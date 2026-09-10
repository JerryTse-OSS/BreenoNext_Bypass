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

/**
 * Xposed module to bypass verification checks in BreenoNext (com.oplus.claw).
 *
 * Supported versions: 170066, 170068, 170069, 170070, 170071, 170072
 *
 * Each version uses different obfuscated class names but shares the same logic.
 * Version detection is done by checking which gate controller class exists.
 */
public class HookEntry implements IXposedHookLoadPackage {

    private static final String TARGET = "com.oplus.claw";
    private static final String TAG = "BreenoNextBypass";

    private ClassLoader cl;
    private int version;

    // Version identifiers (higher number = newer version)
    private static final int V170066 = 170066;
    private static final int V170068 = 170068;
    private static final int V170069 = 170069;
    private static final int V170070 = 170070;
    private static final int V170071 = 170071;
    private static final int V170072 = 170072;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals(TARGET)) return;
        cl = lpparam.classLoader;

        version = detectVersion();
        if (version == 0) {
            XposedBridge.log(TAG + ": Unknown version, skipping");
            return;
        }
        XposedBridge.log(TAG + ": Loaded into " + TARGET + " v" + version);

        hookAccessGate();
        hookPolicyState();
        hookRootDetection();
        hookBetaVerification();
        hookBootloaderCheck();
        hookViewModelRootCheck();
        hookPrecheckBypass();
        hookCachedDecision();
    }

    /**
     * Detect app version by checking which gate controller class exists.
     *
     * The gate controller is the class with d(String) (Denied) and e() (Granted) methods.
     * - 170072: k3 (distinguished from 170069 by t30.a class)
     * - 170071: g3
     * - 170070: n3
     * - 170069: k3
     * - 170066/170068: c3 (distinguished by a0/b0 classes)
     */
    private int detectVersion() {
        // 170071: g3 is the controller
        if (hasMethod("com.oplus.claw.welcome.g3", "d", String.class)) return V170071;
        // 170070: n3 is the controller
        if (hasMethod("com.oplus.claw.welcome.n3", "d", String.class)) return V170070;
        // k3 is the controller in 170069 and 170072
        if (hasMethod("com.oplus.claw.welcome.k3", "d", String.class)) {
            // t30.a exists only in 170072 → 170072; else 170069
            if (classExists("t30.a")) return V170072;
            return V170069;
        }
        // 170066/170068: c3 is the controller
        if (hasMethod("com.oplus.claw.welcome.c3", "d", String.class)) {
            if (classExists("com.oplus.claw.welcome.a0")) return V170066;
            return V170068;
        }
        return 0;
    }

    /**
     * Check if a class has a specific method with given parameter types.
     */
    private boolean hasMethod(String className, String methodName, Class<?>... paramTypes) {
        try {
            Class<?> cls = XposedHelpers.findClass(className, cl);
            cls.getDeclaredMethod(methodName, paramTypes);
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    // ==================== Version-specific class getters ====================

    /**
     * Gate controller class that manages access state.
     * - 170066/170068: c3
     * - 170069: k3
     * - 170070: n3
     * - 170071: g3
     * - 170072: k3
     */
    private String gateControllerClass() {
        if (version <= V170068) return "c3";
        if (version == V170069) return "k3";
        if (version == V170070) return "n3";
        if (version == V170071) return "g3";
        return "k3";
    }

    /**
     * Granted state class with long constructor.
     * - 170066/170068: z2(long)
     * - 170069: h2(i2, Long)
     * - 170070: k2(l2, Long)
     * - 170071: d3(long)
     * - 170072: h3(long)
     */
    private String grantedStateClass() {
        if (version <= V170068) return "z2";
        if (version == V170069) return "h2";
        if (version == V170070) return "k2";
        if (version == V170071) return "d3";
        return "h3";
    }

    /**
     * Policy state holder class with AtomicReference field 'b'.
     * - 170066/170068: k4
     * - 170069: n2
     * - 170070: q2
     * - 170071: k2
     * - 170072: n2
     */
    private String policyHolderClass() {
        if (version <= V170068) return "k4";
        if (version == V170069) return "n2";
        if (version == V170070) return "q2";
        if (version == V170071) return "k2";
        return "n2";
    }

    /**
     * Verdict enum class (Pending/Trusted/Compromised).
     * - 170066/170068: h4
     * - 170069: k2
     * - 170070: n2
     * - 170071: h2
     * - 170072: k2
     */
    private String verdictEnumClass() {
        if (version <= V170068) return "h4";
        if (version == V170069) return "k2";
        if (version == V170070) return "n2";
        if (version == V170071) return "h2";
        return "k2";
    }

    /**
     * Bootloader/root check class with method 'i(Context)'.
     * - 170066/170068: s4
     * - 170069: w4
     * - 170070: z4
     * - 170071: s4
     * - 170072: w4
     */
    private String bootCheckClass() {
        if (version <= V170068) return "s4";
        if (version == V170069) return "w4";
        if (version == V170070) return "z4";
        if (version == V170071) return "s4";
        return "w4";
    }

    /**
     * ViewModel class with f(String, c) and h(boolean, boolean, String, boolean, c) methods.
     * - 170066/170068: m1
     * - 170069: n1
     * - 170070: q1
     * - 170071: k1
     * - 170072: o1
     */
    private String viewModelClass() {
        if (version <= V170068) return "m1";
        if (version == V170069) return "n1";
        if (version == V170070) return "q1";
        if (version == V170071) return "k1";
        return "o1";
    }

    /**
     * Coroutine continuation class for ViewModel methods.
     * - 170066/170068: x10.c
     * - 170069: e20.c
     * - 170070: h20.c
     * - 170071: y20.c
     * - 170072: k30.c
     */
    private String continuationClass() {
        if (version <= V170068) return "x10.c";
        if (version == V170069) return "e20.c";
        if (version == V170070) return "h20.c";
        if (version == V170071) return "y20.c";
        return "k30.c";
    }

    /**
     * Idle state class (precheck bypass target).
     * - 170066/170068: c1.f17845a
     * - 170069: e1.f15227a
     * - 170070: f1.f15998a
     * - 170071: b1.f17861a
     * - 170072: e1.f15787a
     */
    private String idleStateClass() {
        if (version <= V170068) return "c1";
        if (version == V170069) return "e1";
        if (version == V170070) return "f1";
        if (version == V170071) return "b1";
        return "e1";
    }

    private String idleStateField() {
        if (version <= V170068) return "f17845a";
        if (version == V170069) return "f15227a";
        if (version == V170070) return "f15998a";
        if (version == V170071) return "f17861a";
        return "f15787a";
    }

    /**
     * Cached decision class returned by p.b(Context).
     * - 170066/170068: h2(long, String, String, boolean)
     * - 170069: o2(long, String, String, boolean)
     * - 170070: r2(long, String, String, boolean)
     * - 170071: l2(long, String, String, boolean)
     * - 170072: o2(long, String, String, boolean)
     */
    private String cachedDecisionClass() {
        if (version <= V170068) return "h2";
        if (version == V170069) return "o2";
        if (version == V170070) return "r2";
        if (version == V170071) return "l2";
        return "o2";
    }

    /**
     * Beta verification method parameter types.
     * Each version uses different parameter type classes.
     */
    private Object[] betaVerifyParamTypes() {
        String cont = continuationClass();
        if (version <= V170068) {
            // 170066: k4.b(String, Boolean, g20.a, y20.x, x10.c)
            // 170068: k4.b(String, Boolean, g20.a, y20.y, x10.c)
            String third = version == V170066 ? "y20.x" : "y20.y";
            return new Object[]{String.class, Boolean.class, findClass("g20.a"), findClass(third), findClass(cont)};
        }
        if (version == V170069) {
            // 170069: n2.b(String, Boolean, n20.a, f30.x, e20.c)
            return new Object[]{String.class, Boolean.class, findClass("n20.a"), findClass("f30.x"), findClass(cont)};
        }
        if (version == V170070) {
            // 170070: q2.b(String, Boolean, q20.a, i30.x, h20.c)
            return new Object[]{String.class, Boolean.class, findClass("q20.a"), findClass("i30.x"), findClass(cont)};
        }
        if (version == V170071) {
            // 170071: k2.b(String, Boolean, h30.a, z30.x, y20.c)
            return new Object[]{String.class, Boolean.class, findClass("h30.a"), findClass("z30.x"), findClass(cont)};
        }
        // 170072: n2.b(String, Boolean, t30.a, l40.x, k30.c)
        return new Object[]{String.class, Boolean.class, findClass("t30.a"), findClass("l40.x"), findClass(cont)};
    }

    // ==================== Hook implementations ====================

    /**
     * Hook 1: Access Gate Bypass
     *
     * Blocks the gate from being set to Denied state.
     * Also hooks the fallback method to return Ready/Allowed instead of "not ready".
     *
     * Hook points:
     * - gate.d(String) → sets gate to Denied (replaced with no-op)
     * - gate.f() → fallback that returns "not ready" (replaced with Ready state)
     */
    private void hookAccessGate() {
        String gate = "com.oplus.claw.welcome." + gateControllerClass();

        // Block gate.d(String) from setting Denied state
        boolean dOk = tryHook(gate, "d", String.class, XC_MethodReplacement.DO_NOTHING);
        XposedBridge.log(TAG + ": hookAccessGate " + gate + ".d(String) — " + (dOk ? "OK" : "FAILED"));

        // Replace gate.f() fallback with Ready/Allowed state
        try {
            final Object readyState = createReadyState();
            if (readyState != null) {
                boolean fOk = tryHook(gate, "f", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(readyState);
                    }
                });
                XposedBridge.log(TAG + ": hookAccessGate " + gate + ".f() → Ready — " + (fOk ? "OK" : "FAILED"));
            }
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookAccessGate fallback error — " + e.getMessage());
        }
    }

    /**
     * Create a Ready/Allowed state object for the current version.
     *
     * - 170066/170068: z2(long) extends b3
     * - 170069: h2(i2, Long) extends g2
     * - 170070: k2(l2, Long) extends m2
     * - 170071: d3(long) extends f3
     */
    private Object createReadyState() {
        try {
            if (version <= V170068) {
                // 170066/170068: z2(long) is the Granted state
                Class<?> z2Class = XposedHelpers.findClass("com.oplus.claw.welcome.z2", cl);
                return z2Class.getConstructor(long.class).newInstance(System.currentTimeMillis());
            }
            if (version == V170069) {
                // 170069: h2(i2, Long) is the Allowed state
                Class<?> h2Class = XposedHelpers.findClass("com.oplus.claw.welcome.h2", cl);
                Object src = findStaticField("com.oplus.claw.welcome.i2", "a");
                if (src == null) src = findStaticField("com.oplus.claw.welcome.i2", "f15306a");
                if (src != null) {
                    return h2Class.getConstructor(src.getClass(), Long.class)
                            .newInstance(src, System.currentTimeMillis());
                }
            }
            if (version == V170070) {
                // 170070: k2(l2, Long) is the Ready state
                Class<?> k2Class = XposedHelpers.findClass("com.oplus.claw.welcome.k2", cl);
                Object src = findStaticField("com.oplus.claw.welcome.l2", "f16102a");
                if (src == null) src = findStaticField("com.oplus.claw.welcome.l2", "a");
                if (src != null) {
                    return k2Class.getConstructor(src.getClass(), Long.class)
                            .newInstance(src, System.currentTimeMillis());
                }
            }
            if (version == V170071) {
                // 170071: d3(long) is the Granted state
                Class<?> d3Class = XposedHelpers.findClass("com.oplus.claw.welcome.d3", cl);
                return d3Class.getConstructor(long.class).newInstance(System.currentTimeMillis());
            }
            if (version == V170072) {
                // 170072: h3(long) is the Granted state
                Class<?> h3Class = XposedHelpers.findClass("com.oplus.claw.welcome.h3", cl);
                return h3Class.getConstructor(long.class).newInstance(System.currentTimeMillis());
            }
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": createReadyState error — " + e.getMessage());
        }
        return null;
    }

    /**
     * Hook 2: Policy State Bypass
     *
     * Intercepts AtomicReference.set() to block enforced+pending state
     * which would cause "access_error_model_access_not_ready" errors.
     *
     * Hook point:
     * - AtomicReference.set(Object) on the policy reference
     *   Blocks when: isEnforced=true AND verdict=Pending
     */
    private void hookPolicyState() {
        try {
            String holder = "com.oplus.claw.welcome." + policyHolderClass();
            String verdict = "com.oplus.claw.welcome." + verdictEnumClass();

            // Find the AtomicReference holding the policy state
            Object refObj = findStaticField(holder, "b");
            if (refObj == null) {
                XposedBridge.log(TAG + ": hookPolicyState — ref not found in " + holder);
                return;
            }

            // Find the Pending verdict constant
            Object pending = findStaticField(verdict, "a");
            if (pending == null) {
                XposedBridge.log(TAG + ": hookPolicyState — Pending not found in " + verdict);
                return;
            }

            final Object policyRef = refObj;
            final Object pendingVerdict = pending;

            Method setMethod = AtomicReference.class.getDeclaredMethod("set", Object.class);
            XposedBridge.hookMethod(setMethod, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.thisObject != policyRef) return;
                    Object state = param.args[0];
                    if (state == null) return;

                    boolean enforced = getBoolField(state, "a");
                    Object verdict = getObjField(state, "c");
                    if (enforced && verdict == pendingVerdict) {
                        param.setResult(null);
                        XposedBridge.log(TAG + ": Blocked policy → enforced+pending");
                    }
                }
            });
            XposedBridge.log(TAG + ": hookPolicyState — OK");
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookPolicyState error — " + e.getMessage());
        }
    }

    /**
     * Hook 3: Root Detection Bypass
     *
     * Returns false for root detection checks.
     * The root detection class varies between versions and even builds.
     * We try multiple known classes as fallback.
     *
     * Hook points (tried in order):
     * - 170072: a00.b.f()
     * - 170071: as.b.g()
     * - 170070: az.b.e()
     * - 170069: ap.b.g()
     * - 170068: com.oplus.anim.w.e()
     * - 170066: aq.e6.f()
     */
    private void hookRootDetection() {
        XC_MethodHook hook = setResultHook(false);

        if (version >= V170072) {
            if (tryHook("a00.b", "f", hook)) return;
        }
        if (version >= V170071) {
            if (tryHook("as.b", "g", hook)) return;
        }
        if (version >= V170070) {
            if (tryHook("az.b", "e", hook)) return;
        }
        if (version >= V170069) {
            if (tryHook("ap.b", "g", hook)) return;
        }
        if (version >= V170068) {
            if (tryHook("com.oplus.anim.w", "e", hook)) return;
        }
        tryHook("aq.e6", "f", hook);
    }

    /**
     * Hook 4: Beta Verification Bypass
     *
     * Returns false for the device access policy check.
     *
     * Hook points:
     * - 170066: k4.b(String, Boolean, g20.a, y20.x, x10.c)
     * - 170068: k4.b(String, Boolean, g20.a, y20.y, x10.c)
     * - 170069: n2.b(String, Boolean, n20.a, f30.x, e20.c)
     * - 170070: q2.b(String, Boolean, q20.a, i30.x, h20.c)
     * - 170071: k2.b(String, Boolean, h30.a, z30.x, y20.c)
     * - 170072: n2.b(String, Boolean, t30.a, l40.x, k30.c)
     */
    private void hookBetaVerification() {
        String cls = "com.oplus.claw.welcome." + policyHolderClass();
        Object[] params = betaVerifyParamTypes();
        Object[] args = new Object[params.length + 1];
        System.arraycopy(params, 0, args, 0, params.length);
        args[params.length] = setResultHook(false);

        boolean ok = tryHookParams(cls, "b", args);
        XposedBridge.log(TAG + ": hookBetaVerification " + cls + ".b(...) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 5: Bootloader/Root Check Bypass
     *
     * Returns false for the combined root+bootloader integrity check.
     *
     * Hook points:
     * - 170066/170068: s4.i(Context)
     * - 170069: w4.i(Context)
     * - 170070: z4.i(Context)
     * - 170071: s4.i(Context)
     * - 170072: w4.i(Context)
     */
    private void hookBootloaderCheck() {
        String cls = "com.oplus.claw.welcome." + bootCheckClass();
        boolean ok = tryHook(cls, "i", Context.class, setResultHook(false));
        XposedBridge.log(TAG + ": hookBootloaderCheck " + cls + ".i(Context) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 6: ViewModel Root Check Bypass
     *
     * Returns null to skip root status query in ViewModel.
     *
     * Hook points:
     * - 170066/170068: m1.f(String, x10.c)
     * - 170069: n1.f(String, e20.c)
     * - 170070: q1.f(String, h20.c)
     * - 170071: k1.f(String, y20.c)
     * - 170072: o1.f(String, k30.c)
     */
    private void hookViewModelRootCheck() {
        String cls = "com.oplus.claw.welcome." + viewModelClass();
        String cont = continuationClass();
        boolean ok = tryHookParams(cls, "f", String.class, findClass(cont), setResultHook((Object) null));
        XposedBridge.log(TAG + ": hookViewModelRootCheck " + cls + ".f(...) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 7: Precheck Bypass
     *
     * Returns Idle state to skip the /precheck API call.
     *
     * Hook points:
     * - 170066/170068: m1.h(boolean, boolean, String, boolean, x10.c)
     * - 170069: n1.h(boolean, boolean, String, boolean, e20.c)
     * - 170070: q1.h(boolean, boolean, String, boolean, h20.c)
     * - 170071: k1.h(boolean, boolean, String, boolean, y20.c)
     * - 170072: o1.h(boolean, boolean, String, boolean, k30.c)
     */
    private void hookPrecheckBypass() {
        Object idle = findStaticField("com.oplus.claw.welcome." + idleStateClass(), idleStateField());
        if (idle == null) {
            XposedBridge.log(TAG + ": hookPrecheckBypass — idle state not found");
            return;
        }

        final Object idleState = idle;
        String cls = "com.oplus.claw.welcome." + viewModelClass();
        String cont = continuationClass();

        boolean ok = tryHookParams(cls, "h",
                boolean.class, boolean.class, String.class, boolean.class,
                findClass(cont), new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(idleState);
                    }
                });
        XposedBridge.log(TAG + ": hookPrecheckBypass " + cls + ".h(...) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 8: Cached Decision Bypass
     *
     * Returns a cached decision with isAllowed=true.
     *
     * Hook points:
     * - p.b(Context) returns:
     *   - 170066/170068: h2(long, String, String, boolean)
     *   - 170069: o2(long, String, String, boolean)
     *   - 170070: r2(long, String, String, boolean)
     *   - 170071: l2(long, String, String, boolean)
     *   - 170072: o2(long, String, String, boolean)
     */
    private void hookCachedDecision() {
        try {
            final String clsName = "com.oplus.claw.welcome." + cachedDecisionClass();
            final Class<?> cls = XposedHelpers.findClass(clsName, cl);

            XC_MethodHook hook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        param.setResult(cls.getConstructor(long.class, String.class, String.class, boolean.class)
                                .newInstance(System.currentTimeMillis(), "", "", true));
                    } catch (Throwable ignored) {}
                }
            };

            boolean ok = tryHook("com.oplus.claw.welcome.p", "b", Context.class, hook);
            XposedBridge.log(TAG + ": hookCachedDecision " + clsName + " — " + (ok ? "OK" : "FAILED"));
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookCachedDecision error — " + e.getMessage());
        }
    }

    // ==================== Utility methods ====================

    private boolean classExists(String className) {
        try {
            XposedHelpers.findClass(className, cl);
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    private boolean tryHook(String className, String methodName, XC_MethodHook hook) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, hook);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean tryHook(String className, String methodName, Class<?> p1, XC_MethodHook hook) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, p1, hook);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean tryHookParams(String className, String methodName, Object... paramTypesAndCallback) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, paramTypesAndCallback);
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

    private static boolean getBoolField(Object obj, String name) {
        try {
            return XposedHelpers.getBooleanField(obj, name);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Object getObjField(Object obj, String name) {
        try {
            return XposedHelpers.getObjectField(obj, name);
        } catch (Throwable ignored) {
            return null;
        }
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
