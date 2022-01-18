/*
 * Copyright (c) 2019, 2021, Red Hat, Inc.
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package java.security;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Properties;

import sun.security.util.Debug;

/**
 * Internal class to align OpenJDK with global crypto-policies.
 * Called from java.security.Security class initialization,
 * during startup.
 *
 */

final class SystemConfigurator {

    private static final Debug sdebug =
            Debug.getInstance("properties");

    private static final String CRYPTO_POLICIES_BASE_DIR =
            "/etc/crypto-policies";

    private static final String CRYPTO_POLICIES_JAVA_CONFIG =
            CRYPTO_POLICIES_BASE_DIR + "/back-ends/java.config";

    private static boolean systemFipsEnabled = false;
    private static boolean plainKeySupportEnabled = false;

    private static final String SYSTEMCONF_NATIVE_LIB = "systemconf";

    private static native boolean getSystemFIPSEnabled()
            throws IOException;

    static {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                System.loadLibrary(SYSTEMCONF_NATIVE_LIB);
                return null;
            }
        });
    }

    /*
     * Invoked when java.security.Security class is initialized, if
     * java.security.disableSystemPropertiesFile property is not set and
     * security.useSystemPropertiesFile is true.
     */
    static boolean configureSysProps(Properties props) {
        boolean loadedProps = false;

        try (BufferedInputStream bis =
                new BufferedInputStream(
                        new FileInputStream(CRYPTO_POLICIES_JAVA_CONFIG))) {
            props.load(bis);
            loadedProps = true;
            if (sdebug != null) {
                sdebug.println("reading system security properties file " +
                        CRYPTO_POLICIES_JAVA_CONFIG);
                sdebug.println(props.toString());
            }
        } catch (IOException e) {
            if (sdebug != null) {
                sdebug.println("unable to load security properties from " +
                        CRYPTO_POLICIES_JAVA_CONFIG);
                e.printStackTrace();
            }
        }
        return loadedProps;
    }

    /*
     * Invoked at the end of java.security.Security initialisation
     * if java.security properties have been loaded
     */
    static boolean configureFIPS(Properties props) {
        boolean loadedProps = false;

        try {
            if (enableFips()) {
                if (sdebug != null) { sdebug.println("FIPS mode detected"); }
                // Remove all security providers
                Iterator<Entry<Object, Object>> i = props.entrySet().iterator();
                while (i.hasNext()) {
                    Entry<Object, Object> e = i.next();
                    if (((String) e.getKey()).startsWith("security.provider")) {
                        if (sdebug != null) { sdebug.println("Removing provider: " + e); }
                        i.remove();
                    }
                }
                // Add FIPS security providers
                String fipsProviderValue = null;
                for (int n = 1;
                     (fipsProviderValue = (String) props.get("fips.provider." + n)) != null; n++) {
                    String fipsProviderKey = "security.provider." + n;
                    if (sdebug != null) {
                        sdebug.println("Adding provider " + n + ": " +
                                fipsProviderKey + "=" + fipsProviderValue);
                    }
                    props.put(fipsProviderKey, fipsProviderValue);
                }
                // Add other security properties
                String keystoreTypeValue = (String) props.get("fips.keystore.type");
                if (keystoreTypeValue != null) {
                    String nonFipsKeystoreType = props.getProperty("keystore.type");
                    props.put("keystore.type", keystoreTypeValue);
                    if (keystoreTypeValue.equals("PKCS11")) {
                        // If keystore.type is PKCS11, javax.net.ssl.keyStore
                        // must be "NONE". See JDK-8238264.
                        System.setProperty("javax.net.ssl.keyStore", "NONE");
                    }
                    if (System.getProperty("javax.net.ssl.trustStoreType") == null) {
                        // If no trustStoreType has been set, use the
                        // previous keystore.type under FIPS mode. In
                        // a default configuration, the Trust Store will
                        // be 'cacerts' (JKS type).
                        System.setProperty("javax.net.ssl.trustStoreType",
                                nonFipsKeystoreType);
                    }
                    if (sdebug != null) {
                        sdebug.println("FIPS mode default keystore.type = " +
                                keystoreTypeValue);
                        sdebug.println("FIPS mode javax.net.ssl.keyStore = " +
                                System.getProperty("javax.net.ssl.keyStore", ""));
                        sdebug.println("FIPS mode javax.net.ssl.trustStoreType = " +
                                System.getProperty("javax.net.ssl.trustStoreType", ""));
                    }
                }
                loadedProps = true;
                systemFipsEnabled = true;
                String plainKeySupport = System.getProperty("com.redhat.fips.plainKeySupport",
                                                            "true");
                plainKeySupportEnabled = !"false".equals(plainKeySupport);
                if (sdebug != null) {
                    if (plainKeySupportEnabled) {
                        sdebug.println("FIPS support enabled with plain key support");
                    } else {
                        sdebug.println("FIPS support enabled without plain key support");
                    }
                }
            }
        } catch (Exception e) {
            if (sdebug != null) {
                sdebug.println("unable to load FIPS configuration");
                e.printStackTrace();
            }
        }
        return loadedProps;
    }

    /**
     * Returns whether or not global system FIPS alignment is enabled.
     *
     * Value is always 'false' before java.security.Security class is
     * initialized.
     *
     * Call from out of this package through SharedSecrets:
     *   SharedSecrets.getJavaSecuritySystemConfiguratorAccess()
     *           .isSystemFipsEnabled();
     *
     * @return  a boolean value indicating whether or not global
     *          system FIPS alignment is enabled.
     */
    static boolean isSystemFipsEnabled() {
        return systemFipsEnabled;
    }

    /**
     * Returns {@code true} if system FIPS alignment is enabled
     * and plain key support is allowed.  Plain key support is
     * enabled by default but can be disabled with
     * {@code -Dcom.redhat.fips.plainKeySupport=false}.
     *
     * @return a boolean indicating whether plain key support
     *         should be enabled.
     */
    static boolean isPlainKeySupportEnabled() {
        return plainKeySupportEnabled;
    }

    /*
     * OpenJDK FIPS mode will be enabled only if the com.redhat.fips
     * system property is true (default) and the system is in FIPS mode.
     *
     * There are 2 possible ways in which OpenJDK detects that the system
     * is in FIPS mode: 1) if the NSS SECMOD_GetSystemFIPSEnabled API is
     * available at OpenJDK's built-time, it is called; 2) otherwise, the
     * /proc/sys/crypto/fips_enabled file is read.
     */
    private static boolean enableFips() throws Exception {
        boolean shouldEnable = Boolean.valueOf(System.getProperty("com.redhat.fips", "true"));
        if (shouldEnable) {
            if (sdebug != null) {
                sdebug.println("Calling getSystemFIPSEnabled (libsystemconf)...");
            }
            try {
                shouldEnable = getSystemFIPSEnabled();
                if (sdebug != null) {
                    sdebug.println("Call to getSystemFIPSEnabled (libsystemconf) returned: "
                            + shouldEnable);
                }
                return shouldEnable;
            } catch (IOException e) {
                if (sdebug != null) {
                    sdebug.println("Call to getSystemFIPSEnabled (libsystemconf) failed:");
                    sdebug.println(e.getMessage());
                }
                throw e;
            }
        } else {
            return false;
        }
    }
}
