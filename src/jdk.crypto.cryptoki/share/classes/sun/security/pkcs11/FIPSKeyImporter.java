/*
 * Copyright (c) 2021, Red Hat, Inc.
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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Cipher;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.IvParameterSpec;

import sun.security.jca.JCAUtil;
import sun.security.pkcs11.TemplateManager;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import sun.security.rsa.RSAUtil.KeyType;
import sun.security.util.Debug;
import sun.security.util.ECUtil;

final class FIPSKeyImporter {

    private static final Debug debug =
            Debug.getInstance("sunpkcs11");

    private static P11Key importerKey = null;
    private static final ReentrantLock importerKeyLock = new ReentrantLock();
    private static CK_MECHANISM importerKeyMechanism = null;
    private static Cipher importerCipher = null;

    private static Provider sunECProvider = null;
    private static final ReentrantLock sunECProviderLock = new ReentrantLock();

    private static KeyFactory DHKF = null;
    private static final ReentrantLock DHKFLock = new ReentrantLock();

    static Long importKey(SunPKCS11 sunPKCS11, long hSession, CK_ATTRIBUTE[] attributes)
            throws PKCS11Exception {
        long keyID = -1;
        Token token = sunPKCS11.getToken();
        if (debug != null) {
            debug.println("Private or Secret key will be imported in" +
                    " system FIPS mode.");
        }
        if (importerKey == null) {
            importerKeyLock.lock();
            try {
                if (importerKey == null) {
                    if (importerKeyMechanism == null) {
                        // Importer Key creation has not been tried yet. Try it.
                        createImporterKey(token);
                    }
                    if (importerKey == null || importerCipher == null) {
                        if (debug != null) {
                            debug.println("Importer Key could not be" +
                                    " generated.");
                        }
                        throw new PKCS11Exception(CKR_GENERAL_ERROR);
                    }
                    if (debug != null) {
                        debug.println("Importer Key successfully" +
                                " generated.");
                    }
                }
            } finally {
                importerKeyLock.unlock();
            }
        }
        long importerKeyID = importerKey.getKeyID();
        try {
            byte[] keyBytes = null;
            byte[] encKeyBytes = null;
            long keyClass = 0L;
            long keyType = 0L;
            Map<Long, CK_ATTRIBUTE> attrsMap = new HashMap<>();
            for (CK_ATTRIBUTE attr : attributes) {
                if (attr.type == CKA_CLASS) {
                    keyClass = attr.getLong();
                } else if (attr.type == CKA_KEY_TYPE) {
                    keyType = attr.getLong();
                }
                attrsMap.put(attr.type, attr);
            }
            BigInteger v = null;
            if (keyClass == CKO_PRIVATE_KEY) {
                if (keyType == CKK_RSA) {
                    if (debug != null) {
                        debug.println("Importing an RSA private key...");
                    }
                    keyBytes = sun.security.rsa.RSAPrivateCrtKeyImpl.newKey(
                            KeyType.RSA,
                            null,
                            ((v = attrsMap.get(CKA_MODULUS).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_PUBLIC_EXPONENT).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_PRIVATE_EXPONENT).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_PRIME_1).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_PRIME_2).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_EXPONENT_1).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_EXPONENT_2).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_COEFFICIENT).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO
                            ).getEncoded();
                } else if (keyType == CKK_DSA) {
                    if (debug != null) {
                        debug.println("Importing a DSA private key...");
                    }
                    keyBytes = new sun.security.provider.DSAPrivateKey(
                            ((v = attrsMap.get(CKA_VALUE).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_PRIME).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_SUBPRIME).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_BASE).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO
                            ).getEncoded();
                    if (token.config.getNssNetscapeDbWorkaround() &&
                            attrsMap.get(CKA_NETSCAPE_DB) == null) {
                        attrsMap.put(CKA_NETSCAPE_DB,
                                new CK_ATTRIBUTE(CKA_NETSCAPE_DB, BigInteger.ZERO));
                    }
                } else if (keyType == CKK_EC) {
                    if (debug != null) {
                        debug.println("Importing an EC private key...");
                    }
                    if (sunECProvider == null) {
                        sunECProviderLock.lock();
                        try {
                            if (sunECProvider == null) {
                                sunECProvider = Security.getProvider("SunEC");
                            }
                        } finally {
                            sunECProviderLock.unlock();
                        }
                    }
                    keyBytes = ECUtil.generateECPrivateKey(
                            ((v = attrsMap.get(CKA_VALUE).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ECUtil.getECParameterSpec(sunECProvider,
                                    attrsMap.get(CKA_EC_PARAMS).getByteArray()))
                            .getEncoded();
                    if (token.config.getNssNetscapeDbWorkaround() &&
                            attrsMap.get(CKA_NETSCAPE_DB) == null) {
                        attrsMap.put(CKA_NETSCAPE_DB,
                                new CK_ATTRIBUTE(CKA_NETSCAPE_DB, BigInteger.ZERO));
                    }
                } else if (keyType == CKK_DH) {
                    if (debug != null) {
                        debug.println("Importing a Diffie-Hellman private key...");
                    }
                    if (DHKF == null) {
                        DHKFLock.lock();
                        try {
                            if (DHKF == null) {
                                DHKF = KeyFactory.getInstance(
                                        "DH", P11Util.getSunJceProvider());
                            }
                        } finally {
                            DHKFLock.unlock();
                        }
                    }
                    DHPrivateKeySpec spec = new DHPrivateKeySpec
                            (((v = attrsMap.get(CKA_VALUE).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_PRIME).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO,
                            ((v = attrsMap.get(CKA_BASE).getBigInteger()) != null)
                                    ? v : BigInteger.ZERO);
                    keyBytes = DHKF.generatePrivate(spec).getEncoded();
                    if (token.config.getNssNetscapeDbWorkaround() &&
                            attrsMap.get(CKA_NETSCAPE_DB) == null) {
                        attrsMap.put(CKA_NETSCAPE_DB,
                                new CK_ATTRIBUTE(CKA_NETSCAPE_DB, BigInteger.ZERO));
                    }
                } else {
                    if (debug != null) {
                        debug.println("Unrecognized private key type.");
                    }
                    throw new PKCS11Exception(CKR_GENERAL_ERROR);
                }
            } else if (keyClass == CKO_SECRET_KEY) {
                if (debug != null) {
                    debug.println("Importing a secret key...");
                }
                keyBytes = attrsMap.get(CKA_VALUE).getByteArray();
            }
            if (keyBytes == null || keyBytes.length == 0) {
                if (debug != null) {
                    debug.println("Private or secret key plain bytes could" +
                            " not be obtained. Import failed.");
                }
                throw new PKCS11Exception(CKR_GENERAL_ERROR);
            }
            importerCipher.init(Cipher.ENCRYPT_MODE, importerKey,
                    new IvParameterSpec((byte[])importerKeyMechanism.pParameter),
                    null);
            attributes = new CK_ATTRIBUTE[attrsMap.size()];
            attrsMap.values().toArray(attributes);
            encKeyBytes = importerCipher.doFinal(keyBytes);
            attributes = token.getAttributes(TemplateManager.O_IMPORT,
                    keyClass, keyType, attributes);
            keyID = token.p11.C_UnwrapKey(hSession,
                    importerKeyMechanism, importerKeyID, encKeyBytes, attributes);
            if (debug != null) {
                debug.println("Imported key ID: " + keyID);
            }
        } catch (Throwable t) {
            throw new PKCS11Exception(CKR_GENERAL_ERROR);
        } finally {
            importerKey.releaseKeyID();
        }
        return Long.valueOf(keyID);
    }

    private static void createImporterKey(Token token) {
        if (debug != null) {
            debug.println("Generating Importer Key...");
        }
        byte[] iv = new byte[16];
        JCAUtil.getSecureRandom().nextBytes(iv);
        importerKeyMechanism = new CK_MECHANISM(CKM_AES_CBC_PAD, iv);
        try {
            CK_ATTRIBUTE[] attributes = token.getAttributes(TemplateManager.O_GENERATE,
                            CKO_SECRET_KEY, CKK_AES, new CK_ATTRIBUTE[] {
                                    new CK_ATTRIBUTE(CKA_CLASS, CKO_SECRET_KEY),
                                    new CK_ATTRIBUTE(CKA_VALUE_LEN, 256 >> 3)});
            Session s = null;
            try {
                s = token.getObjSession();
                long keyID = token.p11.C_GenerateKey(
                        s.id(), new CK_MECHANISM(CKM_AES_KEY_GEN),
                        attributes);
                if (debug != null) {
                    debug.println("Importer Key ID: " + keyID);
                }
                importerKey = (P11Key)P11Key.secretKey(s, keyID, "AES",
                        256 >> 3, null);
            } catch (PKCS11Exception e) {
                // best effort
            } finally {
                token.releaseSession(s);
            }
            if (importerKey != null) {
                importerCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            }
        } catch (Throwable t) {
            // best effort
            importerKey = null;
            importerCipher = null;
            // importerKeyMechanism value is kept initialized to indicate that
            // Importer Key creation has been tried and failed.
        }
    }
}
