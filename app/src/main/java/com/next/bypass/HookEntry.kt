package com.next.bypass

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage

class HookEntry : IXposedHookLoadPackage {

    companion object {
        private const val TARGET = "com.oplus.claw"
        private const val TAG = "BreenoNextBypass"
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET) return
        val cl = lpparam.classLoader
        XposedBridge.log("$TAG: Loaded into $TARGET")

        hookRootDetection(cl)
        hookRootChecker(cl)
        hookBootloaderCheck(cl)
        hookViewModelRootCheck(cl)
        hookPrecheckBypass(cl)
        hookCachedDecision(cl)
        hookHttpResponse(cl)
        hookStreamError(cl)
        hookCustomProvider(cl)
        hookProviderDropdown(cl)
    }

    private fun hookRootDetection(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("aq.e6", cl), "f",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                        XposedBridge.log("$TAG: Bypassed root detection (e6.f)")
                    }
                })
        } catch (_: Throwable) {
            try {
                XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.anim.w", cl), "e",
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = false
                            XposedBridge.log("$TAG: Bypassed root detection (anim.w.e)")
                        }
                    })
            } catch (e: Throwable) {
                XposedBridge.log("$TAG: Failed to hook root detection — ${e.message}")
            }
        }
    }

    private fun hookRootChecker(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("com.oplus.claw.welcome.k4", cl), "b",
                String::class.java, Boolean::class.javaPrimitiveType!!,
                XposedHelpers.findClass("g20.a", cl),
                XposedHelpers.findClass("y20.y", cl),
                XposedHelpers.findClass("x10.c", cl),
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                        XposedBridge.log("$TAG: Bypassed root checker (k4.b)")
                    }
                })
        } catch (_: Throwable) {
        }
    }

    private fun hookBootloaderCheck(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("com.oplus.claw.welcome.s4", cl), "i",
                android.content.Context::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                        XposedBridge.log("$TAG: Bypassed bootloader check (s4.i)")
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook s4.i — ${e.message}")
        }
    }

    private fun hookViewModelRootCheck(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("com.oplus.claw.welcome.m1", cl), "f",
                String::class.java, XposedHelpers.findClass("x10.c", cl),
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                        XposedBridge.log("$TAG: Bypassed ViewModel root check (m1.f)")
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook m1.f — ${e.message}")
        }
    }

    private fun hookPrecheckBypass(cl: ClassLoader) {
        try {
            val e1 = XposedHelpers.findClass("com.oplus.claw.welcome.e1", cl)
            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("com.oplus.claw.welcome.m1", cl), "h",
                Boolean::class.javaPrimitiveType!!, Boolean::class.javaPrimitiveType!!, String::class.java, Boolean::class.javaPrimitiveType!!,
                XposedHelpers.findClass("x10.c", cl),
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = XposedHelpers.newInstance(e1)
                        XposedBridge.log("$TAG: Bypassed /precheck (m1.h)")
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook m1.h — ${e.message}")
        }
    }

    private fun hookCachedDecision(cl: ClassLoader) {
        try {
            val h2 = XposedHelpers.findClass("com.oplus.claw.welcome.h2", cl)
            val handler = object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = XposedHelpers.newInstance(
                        h2, System.currentTimeMillis(), "", "", true
                    )
                    XposedBridge.log("$TAG: Cached decision → Allowed")
                }
            }
            try {
                XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.p", cl), "b",
                    android.content.Context::class.java, handler
                )
            } catch (_: Throwable) {
                XposedHelpers.findAndHookMethod(
                    XposedHelpers.findClass("com.oplus.claw.welcome.o", cl), "b",
                    android.content.Context::class.java, handler
                )
            }
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook cached decision — ${e.message}")
        }
    }

    private fun hookHttpResponse(cl: ClassLoader) {
        try {
            val u2 = XposedHelpers.findClass("com.oplus.claw.welcome.u2", cl)
            val e4 = XposedHelpers.findClass("com.oplus.claw.welcome.e4", cl)
            XposedHelpers.findAndHookMethod(u2, "e",
                e4, String::class.java, String::class.java, Boolean::class.javaPrimitiveType!!,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val resp = param.args[0]
                        val msg = XposedHelpers.getObjectField(resp, "b") as? String ?: return
                        if (msg.contains("-12002") || msg.contains("-12003")) {
                            XposedHelpers.setObjectField(resp, "b", "{\"code\":0,\"message\":\"ok\"}")
                            XposedHelpers.setIntField(resp, "a", 200)
                            XposedHelpers.setBooleanField(resp, "c", true)
                            XposedBridge.log("$TAG: Stripped -12002/-12003 from HTTP response (u2.e)")
                        }
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook u2.e — ${e.message}")
        }
    }

    private fun hookStreamError(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("si.f0", cl), "b",
                String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result ?: return
                        val code = XposedHelpers.getObjectField(result, "c") as? String
                        if (code == "-12002" || code == "-12003") {
                            param.result = null
                            XposedBridge.log("$TAG: Suppressed -12002/-12003 stream error (f0.b)")
                        }
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook si.f0.b — ${e.message}")
        }
    }

    private fun hookCustomProvider(cl: ClassLoader) {
        try {
            val k1 = XposedHelpers.findClass("mh.k1", cl)
            val d0 = XposedHelpers.findClass("si.d0", cl)
            val cont = XposedHelpers.findClass("x10.c", cl)
            val i1 = XposedHelpers.findClass("mh.i1", cl)
            val e0 = XposedHelpers.findClass("r3.e0", cl)

            XposedHelpers.findAndHookMethod(
                XposedHelpers.findClass("si.d", cl), "d",
                k1, d0, Boolean::class.javaPrimitiveType!!, cont,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val baseUrl = XposedHelpers.getObjectField(param.args[0], "d") as? String ?: return
                        if (baseUrl.contains("heytapmobi.com") || baseUrl.contains("wanyol.com")) return
                        param.result = XposedHelpers.newInstance(
                            i1, baseUrl,
                            java.util.LinkedHashMap<String, String>(),
                            XposedHelpers.newInstance(e0, 2),
                            java.util.HashMap<String, String>()
                        )
                        XposedBridge.log("$TAG: Custom provider → $baseUrl")
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook si.d — ${e.message}")
        }
    }

    private fun hookProviderDropdown(cl: ClassLoader) {
        try {
            val b5 = XposedHelpers.findClass("com.oplus.claw.settings.b5", cl)
            XposedHelpers.findAndHookMethod(b5, "b",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val list = param.result as? java.util.List<*> ?: return
                        val tpl = XposedHelpers.getStaticObjectField(b5, "b")
                        if (tpl != null && !list.contains(tpl)) {
                            param.result = java.util.ArrayList(list).apply { add(tpl) }
                            XposedBridge.log("$TAG: Added '自定义' to dropdown")
                        }
                    }
                })
        } catch (e: Throwable) {
            XposedBridge.log("$TAG: Failed to hook b5.b — ${e.message}")
        }
    }
}
