/*
 * Copyright (c) 2022, Red Hat, Inc.
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

package sun.security.pkcs11;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.ProviderException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import sun.security.util.Debug;
import sun.security.util.SecurityProperties;

final class FIPSTokenLoginHandler implements CallbackHandler {

    private static final String FIPS_NSSDB_PIN_PROP = "fips.nssdb.pin";

    private static final Debug debug = Debug.getInstance("sunpkcs11");

    public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException {
        if (!(callbacks[0] instanceof PasswordCallback)) {
            throw new UnsupportedCallbackException(callbacks[0]);
        }
        PasswordCallback pc = (PasswordCallback)callbacks[0];
        pc.setPassword(getFipsNssdbPin());
    }

    private static char[] getFipsNssdbPin() throws ProviderException {
        if (debug != null) {
            debug.println("FIPS: Reading NSS DB PIN for token...");
        }
        String pinProp = SecurityProperties
                .privilegedGetOverridable(FIPS_NSSDB_PIN_PROP);
        if (pinProp != null && !pinProp.isEmpty()) {
            String[] pinPropParts = pinProp.split(":", 2);
            if (pinPropParts.length < 2) {
                throw new ProviderException("Invalid " + FIPS_NSSDB_PIN_PROP +
                        " property value.");
            }
            String prefix = pinPropParts[0].toUpperCase();
            String value = pinPropParts[1];
            String pin = null;
            if (prefix.equals("ENV")) {
                if (debug != null) {
                    debug.println("FIPS: PIN value from the '" + value +
                            "' environment variable.");
                }
                pin = System.getenv(value);
            } else if (prefix.equals("FILE")) {
                if (debug != null) {
                    debug.println("FIPS: PIN value from the '" + value +
                            "' file.");
                }
                pin = getPinFromFile(Paths.get(value));
            } else if (prefix.equals("PIN")) {
                if (debug != null) {
                    debug.println("FIPS: PIN value from the " +
                            FIPS_NSSDB_PIN_PROP + " property.");
                }
                pin = value;
            } else {
                throw new ProviderException("Unsupported prefix for " +
                        FIPS_NSSDB_PIN_PROP + ".");
            }
            if (pin != null && !pin.isEmpty()) {
                if (debug != null) {
                    debug.println("FIPS: non-empty PIN.");
                }
                /*
                 * C_Login in libj2pkcs11 receives the PIN in a char[] and
                 * discards the upper byte of each char, before passing
                 * the value to the NSS Software Token. However, the
                 * NSS Software Token accepts any UTF-8 PIN value. Thus,
                 * expand the PIN here to account for later truncation.
                 */
                byte[] pinUtf8 = pin.getBytes(StandardCharsets.UTF_8);
                char[] pinChar = new char[pinUtf8.length];
                for (int i = 0; i < pinChar.length; i++) {
                    pinChar[i] = (char)(pinUtf8[i] & 0xFF);
                }
                return pinChar;
            }
        }
        if (debug != null) {
            debug.println("FIPS: empty PIN.");
        }
        return new char[] {};
    }

    /*
     * This method extracts the token PIN from the first line of a password
     * file in the same way than NSS modutil. See for example the -newpwfile
     * argument used to change the password for an NSS DB.
     */
    private static String getPinFromFile(Path f) throws ProviderException {
        try (InputStream is =
                Files.newInputStream(f, StandardOpenOption.READ)) {
            /*
             * SECU_FilePasswd in NSS (nss/cmd/lib/secutil.c), used by modutil,
             * reads up to 4096 bytes. In addition, the NSS Software Token
             * does not accept PINs longer than 500 bytes (see SFTK_MAX_PIN
             * in nss/lib/softoken/pkcs11i.h).
             */
            BufferedReader in =
                    new BufferedReader(new InputStreamReader(
                            new ByteArrayInputStream(is.readNBytes(4096)),
                            StandardCharsets.UTF_8));
            return in.readLine();
        } catch (IOException ioe) {
            throw new ProviderException("Error reading " + FIPS_NSSDB_PIN_PROP +
                    " from the '" + f + "' file.", ioe);
        }
    }
}