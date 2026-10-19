package com.cf.msc.sdk;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Environment;
import android.os.Process;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import cn.jpush.android.local.JPushConstants;
import com.cf.msc.sdk.NetHelper;
import com.huawei.hms.support.hianalytics.HiAnalyticsConstant;
import com.umeng.analytics.pro.be;
import com.umeng.analytics.pro.bv;
import com.umeng.ccg.a;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Scanner;
import org.apache.tika.metadata.TikaCoreProperties;
import org.apache.tika.utils.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes2.dex */
public class AppVest {
    static final String TAG = "Appvest";
    static final int UPDATE_INTERVAL = 500;
    static int c = 0;
    static int c1 = 0;
    static int c2 = 0;
    static String deviceID = null;
    static boolean isVpn = false;
    static long mLastUpdateTime = 0;
    static float mLastX = 0.0f;
    static float mLastY = 0.0f;
    static float mLastZ = 0.0f;
    static final int shakeThreshold = 200;

    private static native int JNIInit(String str, String str2);

    public static native int addListeningPort(int i);

    public static native String getClientIP();

    public static native int getHttpLocalPort(String str, int i);

    public static native int getLocalPort(int i);

    public static native String getProxyServerIP();

    private static native String getServerIPAndPortJNI(String str, int i);

    /* JADX INFO: Access modifiers changed from: private */
    public static native int netStatusChangeNotify(byte b);

    public static native int reportSensor(int i, double d);

    private static native int setCredit(String str, int i);

    private static native void setDeviceInfo(String str);

    public static native int setTimeouts(int i, int i2);

    static {
        System.loadLibrary("cf-msc");
        mLastUpdateTime = System.currentTimeMillis();
        mLastX = 0.0f;
        mLastY = 0.0f;
        mLastZ = 0.0f;
        c = 0;
        c1 = 0;
        c2 = 0;
        deviceID = "";
        isVpn = false;
    }

    private static Application getApplication() {
        return (Application) ReflectUtils.getInstanceField("android.app.ActivityThread", ReflectUtils.invokeStaticMethod("android.app.ActivityThread", "currentActivityThread", new Class[0], new Object[0]), "mInitialApplication");
    }

    public static String getAppProcessName(Context context) {
        int iMyPid = Process.myPid();
        for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : ((ActivityManager) context.getSystemService("activity")).getRunningAppProcesses()) {
            if (runningAppProcessInfo.pid == iMyPid) {
                return runningAppProcessInfo.processName;
            }
        }
        return "";
    }

    private static String deviceInfo(Context context) {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("model", Build.MODEL);
            jSONObject.put("manufacturer", Build.MANUFACTURER);
            jSONObject.put("brand", Build.BRAND);
            jSONObject.put("device", Build.DEVICE);
            jSONObject.put("product", Build.PRODUCT);
            jSONObject.put(a.x, Build.VERSION.SDK);
            jSONObject.put("network", NetHelper.getNetStateString(NetHelper.getCurrentNetState(context)));
            jSONObject.put("release", Build.VERSION.RELEASE);
            jSONObject.put(HiAnalyticsConstant.HaKey.BI_KEY_FINGERPRINT, Build.FINGERPRINT);
            jSONObject.put("cpu_abi", Build.CPU_ABI);
            jSONObject.put("board", Build.BOARD);
            jSONObject.put("bootloader", Build.BOOTLOADER);
            jSONObject.put("display", Build.DISPLAY);
            jSONObject.put("host", Build.HOST);
            jSONObject.put("id", Build.ID);
            jSONObject.put("tags", Build.TAGS);
            jSONObject.put("type", Build.TYPE);
            jSONObject.put(be.m, Build.USER);
            jSONObject.put("deviceID", deviceID(context));
            jSONObject.put("isSimulator", isSimulator(context) + "");
            jSONObject.put("configDir", getConfigDir(context));
            jSONObject.put("app_name", getAppPackageName());
            jSONObject.put(bv.o, getAppProcessName(context));
        } catch (JSONException e) {
            Log.w(TAG, e.getMessage(), e);
        }
        return jSONObject.toString();
    }

    private static String deviceID(Context context) {
        if (!TextUtils.isEmpty(deviceID)) {
            return deviceID;
        }
        if (LifecycleTracker.isAppInForeground()) {
            String string = Settings.Secure.getString(context.getContentResolver(), "android_id");
            deviceID = string;
            return TextUtils.isEmpty(string) ? "" : deviceID;
        }
        return deviceID;
    }

    private static String getAppPackageName() {
        PackageManager packageManager;
        PackageInfo packageInfo;
        int i;
        Application application = getApplication();
        if (application != null) {
            try {
                String packageName = application.getPackageName();
                if (packageName != null && (packageManager = application.getPackageManager()) != null && (packageInfo = packageManager.getPackageInfo(packageName, 0)) != null && (i = packageInfo.applicationInfo.labelRes) != -1) {
                    return application.getString(i);
                }
                return packageName;
            } catch (Exception e) {
                e.printStackTrace();
                return "";
            }
        }
        return "";
    }

    private static int isSimulator(Context context) {
        Scanner scanner = null;
        if (context != null) {
            Intent intentRegisterReceiver = context.registerReceiver(null, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
            int intExtra = intentRegisterReceiver.getIntExtra("temperature", -1);
            int intExtra2 = intentRegisterReceiver.getIntExtra("voltage", -1);
            if (intExtra <= 0 || intExtra2 <= 0) {
                return 1;
            }
        }
        try {
            scanner = new Scanner(new File("/proc/cpuinfo"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        if (scanner == null) {
            return 0;
        }
        while (scanner.hasNextLine()) {
            String strNextLine = scanner.nextLine();
            if (strNextLine.toLowerCase().contains("intel") || strNextLine.toLowerCase().contains("amd")) {
                return 1;
            }
        }
        return 0;
    }

    private static String getAppDataDir() {
        Application application = getApplication();
        if (application != null) {
            ApplicationInfo applicationInfo = application.getApplicationInfo();
            application.getApplicationContext().getExternalFilesDir(null);
            if (applicationInfo != null) {
                return applicationInfo.dataDir;
            }
            return "";
        }
        return "";
    }

    private static String getSDCardDir() {
        String str;
        String absolutePath = Environment.getExternalStorageDirectory().getAbsolutePath();
        if (absolutePath != null) {
            if (absolutePath.endsWith(File.pathSeparator)) {
                str = absolutePath + "cf_msc" + File.pathSeparator + "appvest";
            } else {
                str = absolutePath + File.pathSeparator + "cf_msc" + File.pathSeparator + "appvest";
            }
            File file = new File(str);
            if (file.exists()) {
                if (file.isFile()) {
                    file.delete();
                    file.mkdirs();
                }
            }
            file.mkdirs();
            return (file.isDirectory() && file.exists()) ? str : "";
        }
        return "";
    }

    private static String getConfigDir(Context context) {
        String appDataDir = getAppDataDir();
        getSDCardDir();
        return appDataDir.compareTo("") == 0 ? getSDCardDir() : appDataDir;
    }

    private static boolean isProxy() {
        String property = System.getProperty("http.proxyHost");
        String property2 = System.getProperty("http.proxyPort");
        if (property2 == null) {
            property2 = "-1";
        }
        return (TextUtils.isEmpty(property) || Integer.parseInt(property2) == -1) ? false : true;
    }

    private static boolean isVpn() {
        if (LifecycleTracker.isAppInForeground()) {
            try {
                Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                if (networkInterfaces != null) {
                    for (NetworkInterface networkInterface : Collections.list(networkInterfaces)) {
                        if (networkInterface.isUp() && networkInterface.getInterfaceAddresses().size() != 0) {
                            String name = networkInterface.getName();
                            if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("tap")) {
                                isVpn = true;
                                return true;
                            }
                        }
                    }
                }
            } catch (Throwable th) {
                th.printStackTrace();
            }
        }
        return isVpn;
    }

    private static boolean isHook() {
        Application application = getApplication();
        if (application == null) {
            return false;
        }
        return CheckHook.isHook(application);
    }

    private static boolean isVirtual() {
        return CheckVirtual.isRunInVirtual();
    }

    private static String getAppSign() {
        Application application = getApplication();
        if (application == null) {
            return "";
        }
        return SignCheck.getCertificateSHA1Fingerprint(application);
    }

    private static String commandExecutor(String str) throws Throwable {
        Application application = getApplication();
        String str2 = "";
        if (application == null) {
            return "";
        }
        byte currentNetState = NetHelper.getCurrentNetState(application);
        if (currentNetState != 0 && currentNetState != 6) {
            try {
                Process processExec = Runtime.getRuntime().exec(str);
                BufferedReader bufferedReader = null;
                try {
                    processExec.waitFor();
                    BufferedReader bufferedReader2 = new BufferedReader(new InputStreamReader(processExec.getInputStream()));
                    while (true) {
                        try {
                            String line = bufferedReader2.readLine();
                            if (line == null) {
                                break;
                            }
                            str2 = str2 + StringUtils.SPACE + line;
                        } catch (InterruptedException unused) {
                            bufferedReader = bufferedReader2;
                            bufferedReader.close();
                        } catch (Throwable th) {
                            th = th;
                            bufferedReader = bufferedReader2;
                            bufferedReader.close();
                            throw th;
                        }
                    }
                    bufferedReader2.close();
                } catch (InterruptedException unused2) {
                } catch (Throwable th2) {
                    th = th2;
                }
            } catch (IOException unused3) {
            }
        }
        return str2;
    }

    public static int init(String str, String str2) {
        Application application = getApplication();
        if (application == null) {
            Log.e(TAG, "getApplication app is empty, please retry later");
            return -1;
        }
        LifecycleTracker.getInstance().registerIfNeeded(application);
        setDeviceInfo(deviceInfo(application));
        int iJNIInit = JNIInit(str, str2);
        if (iJNIInit == 0) {
            NetHelper netHelper = new NetHelper();
            netHelper.register(application);
            netHelper.addOnNetStateChangedListener(new NetHelper.OnNetStateChangedListener() { // from class: com.cf.msc.sdk.AppVest.1
                @Override // com.cf.msc.sdk.NetHelper.OnNetStateChangedListener
                public void onNetStateChanged(Context context, byte b) {
                    AppVest.netStatusChangeNotify(b);
                }
            });
            SensorManager sensorManager = (SensorManager) application.getSystemService("sensor");
            sensorManager.registerListener(new SensorEventListener() { // from class: com.cf.msc.sdk.AppVest.2
                @Override // android.hardware.SensorEventListener
                public void onAccuracyChanged(Sensor sensor, int i) {
                }

                @Override // android.hardware.SensorEventListener
                public void onSensorChanged(SensorEvent sensorEvent) {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    long j = jCurrentTimeMillis - AppVest.mLastUpdateTime;
                    if (j < 500) {
                        return;
                    }
                    AppVest.mLastUpdateTime = jCurrentTimeMillis;
                    float fAbs = Math.abs(sensorEvent.values[0] - AppVest.mLastX);
                    float fAbs2 = Math.abs(sensorEvent.values[1] - AppVest.mLastY);
                    float fAbs3 = Math.abs(sensorEvent.values[2] - AppVest.mLastZ);
                    AppVest.mLastX = sensorEvent.values[0];
                    AppVest.mLastY = sensorEvent.values[1];
                    AppVest.mLastZ = sensorEvent.values[2];
                    if (AppVest.c == 0) {
                        AppVest.c++;
                        return;
                    }
                    float fMax = Math.max(fAbs, Math.max(fAbs2, fAbs3));
                    if (fMax == 0.0f) {
                        AppVest.reportSensor(1, 0.0d);
                        return;
                    }
                    if (fMax < 0.05d) {
                        AppVest.c1++;
                        AppVest.c2 = 0;
                    } else {
                        AppVest.c1 = 0;
                        AppVest.c2++;
                    }
                    double dSqrt = (Math.sqrt(((fAbs * fAbs) + (fAbs2 * fAbs2)) + (fAbs3 * fAbs3)) / j) * 10000.0d;
                    if (AppVest.c1 > 10) {
                        AppVest.reportSensor(1, dSqrt);
                    }
                    if (AppVest.c2 > 10) {
                        AppVest.reportSensor(0, dSqrt);
                    }
                }
            }, sensorManager.getDefaultSensor(1), 3);
        }
        return iJNIInit;
    }

    public static int init(Application application, String str, String str2) {
        if (application == null) {
            application = getApplication();
        }
        if (application == null) {
            Log.e(TAG, "getApplication app is empty, please retry later");
            return -1;
        }
        LifecycleTracker.getInstance().registerIfNeeded(application);
        setDeviceInfo(deviceInfo(application));
        int iJNIInit = JNIInit(str, str2);
        if (iJNIInit == 0) {
            NetHelper netHelper = new NetHelper();
            netHelper.register(application);
            netHelper.addOnNetStateChangedListener(new NetHelper.OnNetStateChangedListener() { // from class: com.cf.msc.sdk.AppVest.3
                @Override // com.cf.msc.sdk.NetHelper.OnNetStateChangedListener
                public void onNetStateChanged(Context context, byte b) {
                    AppVest.netStatusChangeNotify(b);
                }
            });
            SensorManager sensorManager = (SensorManager) application.getSystemService("sensor");
            sensorManager.registerListener(new SensorEventListener() { // from class: com.cf.msc.sdk.AppVest.4
                @Override // android.hardware.SensorEventListener
                public void onAccuracyChanged(Sensor sensor, int i) {
                }

                @Override // android.hardware.SensorEventListener
                public void onSensorChanged(SensorEvent sensorEvent) {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    long j = jCurrentTimeMillis - AppVest.mLastUpdateTime;
                    if (j < 500) {
                        return;
                    }
                    AppVest.mLastUpdateTime = jCurrentTimeMillis;
                    float fAbs = Math.abs(sensorEvent.values[0] - AppVest.mLastX);
                    float fAbs2 = Math.abs(sensorEvent.values[1] - AppVest.mLastY);
                    float fAbs3 = Math.abs(sensorEvent.values[2] - AppVest.mLastZ);
                    AppVest.mLastX = sensorEvent.values[0];
                    AppVest.mLastY = sensorEvent.values[1];
                    AppVest.mLastZ = sensorEvent.values[2];
                    if (AppVest.c == 0) {
                        AppVest.c++;
                        return;
                    }
                    float fMax = Math.max(fAbs, Math.max(fAbs2, fAbs3));
                    if (fMax == 0.0f) {
                        AppVest.reportSensor(1, 0.0d);
                        return;
                    }
                    if (fMax < 0.05d) {
                        AppVest.c1++;
                        AppVest.c2 = 0;
                    } else {
                        AppVest.c1 = 0;
                        AppVest.c2++;
                    }
                    double dSqrt = (Math.sqrt(((fAbs * fAbs) + (fAbs2 * fAbs2)) + (fAbs3 * fAbs3)) / j) * 10000.0d;
                    if (AppVest.c1 > 10) {
                        AppVest.reportSensor(1, dSqrt);
                    }
                    if (AppVest.c2 > 10) {
                        AppVest.reportSensor(0, dSqrt);
                    }
                }
            }, sensorManager.getDefaultSensor(1), 3);
        }
        return iJNIInit;
    }

    public static SecurityConnection getServerIPAndPort(String str, int i) {
        if (str != null) {
            str = str.toLowerCase().replaceFirst(JPushConstants.HTTP_PRE, "").replaceFirst(JPushConstants.HTTPS_PRE, "").split("/|:")[0];
        }
        String serverIPAndPortJNI = getServerIPAndPortJNI(str, i);
        if (serverIPAndPortJNI.equals("")) {
            return new SecurityConnection("", -1);
        }
        return new SecurityConnection(serverIPAndPortJNI.split(TikaCoreProperties.NAMESPACE_PREFIX_DELIMITER)[0], Integer.valueOf(Integer.valueOf(serverIPAndPortJNI.split(TikaCoreProperties.NAMESPACE_PREFIX_DELIMITER)[1]).intValue()));
    }
}
