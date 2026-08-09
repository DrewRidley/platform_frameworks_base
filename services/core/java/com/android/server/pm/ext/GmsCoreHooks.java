package com.android.server.pm.ext;

import android.Manifest;
import android.app.compat.gms.GmsCorePackageFlag;
import android.content.pm.GosPackageState;
import android.content.pm.PackageManagerInternal;
import android.content.pm.ServiceInfo;
import android.ext.PackageId;
import android.os.SystemProperties;
import android.service.credentials.CredentialProviderService;

import com.android.internal.gmscompat.GmcMediaProjectionService;
import com.android.internal.gmscompat.GmsCompatApp;
import com.android.internal.gmscompat.GmsHooks;
import com.android.internal.gmscompat.client.GmsCorePersistentService;
import com.android.internal.pm.pkg.component.ParsedIntentInfo;
import com.android.internal.pm.pkg.component.ParsedPermission;
import com.android.internal.pm.pkg.component.ParsedService;
import com.android.internal.pm.pkg.component.ParsedServiceImpl;
import com.android.internal.pm.pkg.component.ParsedUsesPermissionImpl;
import com.android.internal.pm.pkg.parsing.ParsingPackage;
import com.android.server.LocalServices;

import java.util.List;

class GmsCoreHooks extends PackageHooks {

    @Override
    public int overridePermissionState(String permission, int userId) {
        if (android.os.Flags.isDevBuild()) {
            if (SystemProperties.getBoolean("sys.gmscore_grant." + permission, false)) {
                return PERMISSION_OVERRIDE_GRANT;
            }
            if (SystemProperties.getBoolean("sys.gmscore_revoke." + permission, false)) {
                return PERMISSION_OVERRIDE_REVOKE;
            }
        }

        int flag = 0;
        switch (permission) {
            case Manifest.permission.USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER:
                flag = GmsCorePackageFlag.GRANT_PERMS_FOR_ICC_AUTHENTICATION;
                break;
            // UWB_PRIVILEGED is signature|privileged, so no third-party app can
            // hold it. Google's design makes GMS the privileged broker: apps use
            // androidx.core.uwb, which binds a backend service inside GMS, and
            // GMS makes the privileged call for them. Sandboxed GMS is an
            // ordinary app (flags=0x0), so there is no broker and UWB is dead
            // for every app that depends on it.
            //
            // Measured on device: GMS does not get denied — it never asks.
            // UwbClient.isAvailable() returns false, GMS drops the client after
            // ~89ms, and UwbServiceImpl is never reached. So no downstream
            // narrowing (see getAnyNonPrivilegedAppInAttributionSource) can even
            // execute until GMS believes it holds this permission.
            case Manifest.permission.UWB_PRIVILEGED:
                flag = GmsCorePackageFlag.GRANT_PERMS_FOR_UWB_PRIVILEGED;
                break;
            // CCC Digital Key ranges over UWB, but it does not start there. The
            // phone and vehicle discover each other over BLE, exchange keys, and
            // negotiate the ranging parameters; only then does UWB ranging begin.
            // BluetoothDevice.getMetadata() is BLUETOOTH_PRIVILEGED, so without
            // this the negotiation dies before UWB is ever reached.
            //
            // Measured on device, during a phone-key session:
            //   GmsCompat: caught SecurityException: Neither user 10206 nor
            //   current process has android.permission.BLUETOOTH_PRIVILEGED
            //
            // This is why granting UWB_PRIVILEGED alone changed nothing:
            // mNumDeviceInitSuccess never incremented because no session was
            // ever negotiated to start.
            case Manifest.permission.BLUETOOTH_PRIVILEGED:
                flag = GmsCorePackageFlag.GRANT_PERMS_FOR_BLUETOOTH_PRIVILEGED;
                break;
            default:
                return NO_PERMISSION_OVERRIDE;
        }

        GosPackageState gosPs = LocalServices.getService(PackageManagerInternal.class)
                .getGosPackageState(PackageId.GMS_CORE_NAME, userId);
        if (gosPs.hasPackageFlag(flag)) {
            return PERMISSION_OVERRIDE_GRANT;
        }
        return PERMISSION_OVERRIDE_REVOKE;
    }

    static class ParsingHooks extends GmsCompatPkgParsingHooks {

        @Override
        public boolean shouldSkipPermissionDefinition(ParsedPermission p) {
            return shouldSkipPermissionDefinition(p.getName());
        }

        @Override
        public void amendParsedService(ParsedServiceImpl s) {
            super.amendParsedService(s);

            if (android.Manifest.permission.BIND_CREDENTIAL_PROVIDER_SERVICE.equals(s.getPermission())) {
                for (ParsedIntentInfo intentInfo : s.getIntents()) {
                    // SYSTEM_SERVICE_INTERFACE is allowed only for preinstalled providers
                    intentInfo.getIntentFilter().replaceAction(CredentialProviderService.SYSTEM_SERVICE_INTERFACE,
                            CredentialProviderService.SERVICE_INTERFACE);
                }
            }
        }

        static boolean shouldSkipPermissionDefinition(String name) {
            switch (name) {
                // These permissions are declared in GmsCompat app instead. They were moved there
                // because of an issue with permissions that have "normal" protectionLevel. If
                // the app that declares a "normal" permission is installed after an app that
                // requests that permission, the permission will not be granted. GmsCompat app
                // is a preinstalled app, it's always present.
                case "com.google.android.c2dm.permission.RECEIVE":
                case "com.google.android.providers.gsf.permission.READ_GSERVICES":
                // This permission is declared in GSF on regular Android. It was moved to GmsCompat
                // app to avoid the need to install GSF, which misbehaves on SDK 35+ due
                // to signature mismatch between itself and GmsCore (GSF and GmsCore use a sharedUid
                // on regular Android)
                case "com.google.android.c2dm.permission.SEND":
                    return true;
                default:
                    return false;
            }
        }

        @Override
        public List<ParsedUsesPermissionImpl> addUsesPermissions() {
            var res = super.addUsesPermissions();
            var l = createUsesPerms(
                    Manifest.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Manifest.permission.READ_PHONE_NUMBERS,
                    Manifest.permission.USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER
            );
            res.addAll(l);
            return res;
        }

        @Override
        public List<ParsedService> addServices(ParsingPackage pkg) {
            ParsedServiceImpl mp = createService(pkg, GmcMediaProjectionService.class.getName());
            mp.setProcessName(GmsHooks.PERSISTENT_GmsCore_PROCESS);
            mp.setForegroundServiceType(ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION);
            mp.setExported(false);

            ParsedServiceImpl persistent = createService(pkg, GmsCorePersistentService.class.getName());
            persistent.setDirectBootAware(true);
            persistent.setProcessName(GmsHooks.PERSISTENT_GmsCore_PROCESS);
            persistent.setPermission(GmsCompatApp.SIGNATURE_PROTECTED_PERMISSION);

            return List.of(mp, persistent);
        }
    }
}
