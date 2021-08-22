/*
 * Copyright (c) 2019, Red Hat, Inc.
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

import java.nio.file.Files;
import java.nio.file.Path;

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sun.security.util.Debug;

/**
 * Internal class to align OpenJDK with global crypto-policies.
 * Called from java.security.Security class initialization,
 * during startup.
 *
 */

class SystemConfigurator {

    private static final Debug sdebug =
            Debug.getInstance("properties");

    private static final String CRYPTO_POLICIES_BASE_DIR =
            "/etc/crypto-policies";

    private static final String CRYPTO_POLICIES_JAVA_CONFIG =
            CRYPTO_POLICIES_BASE_DIR + "/back-ends/java.config";

    private static final String CRYPTO_POLICIES_CONFIG =
            CRYPTO_POLICIES_BASE_DIR + "/config";

    private static final class SecurityProviderInfo {
        int number;
        String key;
        String value;
        SecurityProviderInfo(int number, String key, String value) {
            this.number = number;
            this.key = key;
            this.value = value;
        }
    }

    /*
     * Invoked when java.security.Security class is initialized, if
     * java.security.disableSystemPropertiesFile property is not set and
     * security.useSystemPropertiesFile is true.
     */
    static boolean configure(Properties props) {
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

        try {
            if (enableFips()) {
                if (sdebug != null) { sdebug.println("FIPS mode detected"); }
                loadedProps = false;
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
                loadedProps = true;
            }
        } catch (Exception e) {
            if (sdebug != null) {
                sdebug.println("unable to load FIPS configuration");
                e.printStackTrace();
            }
        }
        return loadedProps;
    }

    /*
     * FIPS is enabled only if crypto-policies are set to "FIPS"
     * and the com.redhat.fips property is true.
     */
    private static boolean enableFips() throws Exception {
        boolean fipsEnabled = Boolean.valueOf(System.getProperty("com.redhat.fips", "true"));
        if (fipsEnabled) {
            String cryptoPoliciesConfig = new String(Files.readAllBytes(Path.of(CRYPTO_POLICIES_CONFIG)));
            if (sdebug != null) { sdebug.println("Crypto config:\n" + cryptoPoliciesConfig); }
            Pattern pattern = Pattern.compile("^FIPS$", Pattern.MULTILINE);
            return pattern.matcher(cryptoPoliciesConfig).find();
        } else {
            return false;
        }
    }
}
