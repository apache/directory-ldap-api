/*
 *   or more contributor license agreements.  See the NOTICE file
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.password;


import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.digest.Crypt;
import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.util.Base64;
import org.apache.directory.api.util.DateUtils;
import org.apache.directory.api.util.Strings;

/**
 * A utility class containing methods related to processing passwords.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PasswordUtil
{

    /** The SHA1 hash length */
    public static final int SHA1_LENGTH = 20;

    /** The SHA256 hash length */
    public static final int SHA256_LENGTH = 32;

    /** The SHA384 hash length */
    public static final int SHA384_LENGTH = 48;

    /** The SHA512 hash length */
    public static final int SHA512_LENGTH = 64;

    /** The MD5 hash length */
    public static final int MD5_LENGTH = 16;

    /** The PKCS5S2 hash length */
    public static final int PKCS5S2_LENGTH = 32;

    /** The CRYPT (DES) hash length */
    public static final int CRYPT_LENGTH = 11;

    /** The CRYPT (MD5) hash length */
    public static final int CRYPT_MD5_LENGTH = 22;

    /** The CRYPT (SHA-256) hash length */
    public static final int CRYPT_SHA256_LENGTH = 43;

    /** The CRYPT (SHA-512) hash length */
    public static final int CRYPT_SHA512_LENGTH = 86;

    /** The CRYPT (BCrypt) hash length */
    public static final int CRYPT_BCRYPT_LENGTH = 31;

    private static final byte[] CRYPT_SALT_CHARS = Strings
        .getBytesUtf8( "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" );


    private PasswordUtil()
    {
    }


    /**
     * Get the algorithm from the stored password. 
     * It can be found on the beginning of the stored password, between 
     * curly brackets.
     * @param credentials the credentials of the user
     * @return the name of the algorithm to use
     */
    public static LdapSecurityConstants findAlgorithm( byte[] credentials )
    {
        if ( ( credentials == null ) || ( credentials.length == 0 ) )
        {
            return null;
        }

        if ( credentials[0] == '{' )
        {
            // get the algorithm
            int pos = 1;

            while ( pos < credentials.length )
            {
                if ( credentials[pos] == '}' )
                {
                    break;
                }

                pos++;
            }

            if ( pos < credentials.length )
            {
                if ( pos == 1 )
                {
                    // We don't have an algorithm : return the credentials as is
                    return null;
                }

                String algorithm = Strings.toLowerCaseAscii( Strings.utf8ToString( credentials, 1, pos - 1 ) );

                // support for crypt additional encryption algorithms (e.g. {crypt}$1$salt$ez2vlPGdaLYkJam5pWs/Y1)
                if ( credentials.length > pos + 3 && credentials[pos + 1] == '$'
                    && Character.isDigit( credentials[pos + 2] ) )
                {
                    if ( credentials[pos + 3] == '$' )
                    {
                        algorithm += Strings.utf8ToString( credentials, pos + 1, 3 );
                    }
                    else if ( credentials.length > pos + 4 && credentials[pos + 4] == '$' )
                    {
                        algorithm += Strings.utf8ToString( credentials, pos + 1, 4 );
                    }
                }

                return LdapSecurityConstants.getAlgorithm( algorithm );
            }
            else
            {
                // We don't have an algorithm
                return null;
            }
        }
        else
        {
            // No '{algo}' part
            return null;
        }
    }


    /**
     * @see #createStoragePassword(byte[], LdapSecurityConstants)
     * 
     * @param credentials The password
     * @param algorithm The algorithm to use
     * @return The resulting byte[] containing the paswword
     */
    public static byte[] createStoragePassword( String credentials, LdapSecurityConstants algorithm )
    {
        return createStoragePassword( Strings.getBytesUtf8( credentials ), algorithm );
    }


    /**
     * create a hashed password in a format that can be stored in the server.
     * If the specified algorithm requires a salt then a random salt of 8 byte size is used
     *  
     * @param credentials the plain text password
     * @param algorithm the hashing algorithm to be applied
     * @return the password after hashing with the given algorithm 
     */
    public static byte[] createStoragePassword( byte[] credentials, LdapSecurityConstants algorithm )
    {
        // check plain text password
        if ( algorithm == null )
        {
            return credentials;
        }

        byte[] salt;

        switch ( algorithm )
        {
            case HASH_METHOD_SSHA:
            case HASH_METHOD_SSHA256:
            case HASH_METHOD_SSHA384:
            case HASH_METHOD_SSHA512:
            case HASH_METHOD_SMD5:
                // we use 8 byte salt always except for "crypt" which needs 2 byte salt
                salt = new byte[8];
                new SecureRandom().nextBytes( salt );
                break;

            case HASH_METHOD_PKCS5S2:
                // we use 16 byte salt for PKCS5S2
                salt = new byte[16];
                new SecureRandom().nextBytes( salt );
                break;

            case HASH_METHOD_CRYPT:
                salt = generateCryptSalt( 2 );
                break;

            case HASH_METHOD_CRYPT_MD5:
            case HASH_METHOD_CRYPT_SHA256:
            case HASH_METHOD_CRYPT_SHA512:
                salt = generateCryptSalt( 8 );
                break;
                
            case HASH_METHOD_CRYPT_BCRYPT:
                salt = Strings.getBytesUtf8( BCrypt.genSalt() );
                break;
    
            default:
                salt = null;
        }

        byte[] hashedPassword = encryptPassword( credentials, algorithm, salt );
        StringBuilder sb = new StringBuilder();

        sb.append( '{' ).append( Strings.upperCase( algorithm.getPrefix() ) ).append( '}' );

        if ( algorithm == LdapSecurityConstants.HASH_METHOD_CRYPT
            || algorithm == LdapSecurityConstants.HASH_METHOD_CRYPT_BCRYPT )
        {
            sb.append( Strings.utf8ToString( salt ) );
            sb.append( Strings.utf8ToString( hashedPassword ) );
        }
        else if ( algorithm == LdapSecurityConstants.HASH_METHOD_CRYPT_MD5
            || algorithm == LdapSecurityConstants.HASH_METHOD_CRYPT_SHA256
            || algorithm == LdapSecurityConstants.HASH_METHOD_CRYPT_SHA512 )
        {
            sb.append( algorithm.getSubPrefix() );
            sb.append( Strings.utf8ToString( salt ) );
            sb.append( '$' );
            sb.append( Strings.utf8ToString( hashedPassword ) );
        }
        else if ( salt != null )
        {
            byte[] hashedPasswordWithSaltBytes = new byte[hashedPassword.length + salt.length];

            if ( algorithm == LdapSecurityConstants.HASH_METHOD_PKCS5S2 )
            {
                merge( hashedPasswordWithSaltBytes, salt, hashedPassword );
            }
            else
            {
                merge( hashedPasswordWithSaltBytes, hashedPassword, salt );
            }

            sb.append( String.valueOf( Base64.encode( hashedPasswordWithSaltBytes ) ) );
        }
        else
        {
            sb.append( String.valueOf( Base64.encode( hashedPassword ) ) );
        }

        return Strings.getBytesUtf8( sb.toString() );
    }


    /**
     * 
     * Compare the credentials.
     * We have at least 6 algorithms to encrypt the password :
     * <ul>
     * <li>- SHA</li>
     * <li>- SSHA (salted SHA)</li>
     * <li>- SHA-2(256, 384 and 512 and their salted versions)</li>
     * <li>- MD5</li>
     * <li>- SMD5 (slated MD5)</li>
     * <li>- PKCS5S2 (PBKDF2)</li>
     * <li>- crypt (unix crypt)</li>
     * <li>- plain text, ie no encryption.</li>
     * </ul>
     * <p>
     *  If we get an encrypted password, it is prefixed by the used algorithm, between
     *  brackets : {SSHA}password ...
     *  </p>
     *  If the password is using SSHA, SMD5 or crypt, some 'salt' is added to the password :
     *  <ul>
     *  <li>- length(password) - 20, starting at 21st position for SSHA</li>
     *  <li>- length(password) - 16, starting at 16th position for SMD5</li>
     *  <li>- length(password) - 2, starting at 3rd position for crypt</li>
     *  </ul>
     *  <p>
     *  For (S)SHA, SHA-256 and (S)MD5, we have to transform the password from Base64 encoded text
     *  to a byte[] before comparing the password with the stored one.
     *  </p>
     *  <p>
     *  For PKCS5S2 the salt is stored in the beginning of the password
     *  </p>
     *  <p>
     *  For crypt, we only have to remove the salt.
     *  </p>
     *  <p>
     *  At the end, we use the digest() method for (S)SHA and (S)MD5, the crypt() method for
     *  the CRYPT algorithm and a straight comparison for PLAIN TEXT passwords.
     *  </p>
     *  <p>
     *  The stored password is always using the unsalted form, and is stored as a bytes array.
     *  </p>
     *
     * @param receivedCredentials the credentials provided by user
     * @param storedCredentials the credentials stored in the server
     * @return true if they are equal, false otherwise
     */
    public static boolean compareCredentials( byte[] receivedCredentials, byte[] storedCredentials )
    {
        LdapSecurityConstants algorithm = findAlgorithm( storedCredentials );

        if ( algorithm != null )
        {
            // Let's get the encrypted part of the stored password
            // We should just keep the password, excluding the algorithm
            // and the salt, if any.
            // But we should also get the algorithm and salt to
            // be able to encrypt the submitted user password in the next step
            PasswordDetails passwordDetails = PasswordUtil.splitCredentials( storedCredentials );

            // Reuse the saltedPassword information to construct the encrypted
            // password given by the user.
            byte[] userPassword = PasswordUtil.encryptPassword( receivedCredentials, passwordDetails.getAlgorithm(),
                passwordDetails.getSalt() );

            return compareBytes( userPassword, passwordDetails.getPassword() );
        }
        else
        {
            return compareBytes( receivedCredentials, storedCredentials );
        }
    }
    
    
    /**
     * Compare two byte[] in a constant time. This is necessary because using an Array.equals() is
     * not Timing attack safe ([1], [2] and [3]), a breach that can be exploited to break some hashes.
     * 
     *  [1] https://en.wikipedia.org/wiki/Timing_attack
     *  [2] http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/
     *  [3] https://cryptocoding.net/index.php/Coding_rules
     */
    private static boolean compareBytes( byte[] provided, byte[] stored )
    {
        if ( stored == null )
        {
            return provided == null;
        }
        else if ( provided == null )
        {
            return false;
        }
        
        // Now, compare the two passwords, using a constant time method
        if ( stored.length != provided.length )
        {
            return false;
        }
        
        // loop on *every* byte in both passwords, and at the end, if one char at least is different, return false.
        int result = 0;
        
        for ( int i = 0; i < stored.length; i++ )
        {
            // If both bytes are equal, xor will be == 0, otherwise it will be != 0 and so will result.
            result |= ( stored[i] ^ provided[i] );
        }
        
        return result == 0;
    }


    /**
     * encrypts the given credentials based on the algorithm name and optional salt
     *
     * @param credentials the credentials to be encrypted
     * @param algorithm the algorithm to be used for encrypting the credentials
     * @param salt value to be used as salt (optional)
     * @return the encrypted credentials
     */
    private static byte[] encryptPassword( byte[] credentials, LdapSecurityConstants algorithm, byte[] salt )
    {
        switch ( algorithm )
        {
            case HASH_METHOD_SHA:
            case HASH_METHOD_SSHA:
                return digest( LdapSecurityConstants.HASH_METHOD_SHA, credentials, salt );

            case HASH_METHOD_SHA256:
            case HASH_METHOD_SSHA256:
                return digest( LdapSecurityConstants.HASH_METHOD_SHA256, credentials, salt );

            case HASH_METHOD_SHA384:
            case HASH_METHOD_SSHA384:
                return digest( LdapSecurityConstants.HASH_METHOD_SHA384, credentials, salt );

            case HASH_METHOD_SHA512:
            case HASH_METHOD_SSHA512:
                return digest( LdapSecurityConstants.HASH_METHOD_SHA512, credentials, salt );

            case HASH_METHOD_MD5:
            case HASH_METHOD_SMD5:
                return digest( LdapSecurityConstants.HASH_METHOD_MD5, credentials, salt );

            case HASH_METHOD_CRYPT:
                String saltWithCrypted = Crypt.crypt( Strings.utf8ToString( credentials ), Strings
                    .utf8ToString( salt ) );
                String crypted = saltWithCrypted.substring( 2 );
                return Strings.getBytesUtf8( crypted );

            case HASH_METHOD_CRYPT_MD5:
            case HASH_METHOD_CRYPT_SHA256:
            case HASH_METHOD_CRYPT_SHA512:
                String saltWithCrypted2 = Crypt.crypt( Strings.utf8ToString( credentials ),
                    algorithm.getSubPrefix() + Strings.utf8ToString( salt ) );
                String crypted2 = saltWithCrypted2.substring( saltWithCrypted2.lastIndexOf( '$' ) + 1 );
                return Strings.getBytesUtf8( crypted2 );

            case HASH_METHOD_CRYPT_BCRYPT:
                String crypted3 = BCrypt.hashPw( Strings.utf8ToString( credentials ), Strings.utf8ToString( salt ) );
                return Strings.getBytesUtf8( crypted3.substring( crypted3.length() - 31 ) );
                
            case HASH_METHOD_PKCS5S2:
                return generatePbkdf2Hash( credentials, algorithm, salt );

            default:
                return credentials;
        }
    }


    /**
     * Compute the hashed password given an algorithm, the credentials and 
     * an optional salt.
     *
     * @param algorithm the algorithm to use
     * @param password the credentials
     * @param salt the optional salt
     * @return the digested credentials
     */
    private static byte[] digest( LdapSecurityConstants algorithm, byte[] password, byte[] salt )
    {
        MessageDigest digest;

        try
        {
            digest = MessageDigest.getInstance( algorithm.getAlgorithm() );
        }
        catch ( NoSuchAlgorithmException e1 )
        {
            return null;
        }

        if ( salt != null )
        {
            digest.update( password );
            digest.update( salt );
            return digest.digest();
        }
        else
        {
            return digest.digest( password );
        }
    }


    /**
     * Decompose the stored password in an algorithm, an eventual salt
     * and the password itself.
     *
     * If the algorithm is SHA, SSHA, MD5 or SMD5, the part following the algorithm
     * is base64 encoded
     *
     * @param credentials The byte[] containing the credentials to split
     * @return The password
     */
    public static PasswordDetails splitCredentials( byte[] credentials )
    {
        LdapSecurityConstants algorithm = findAlgorithm( credentials );

        // check plain text password
        if ( algorithm == null )
        {
            return new PasswordDetails( null, null, credentials );
        }

        int algoLength = algorithm.getPrefix().length() + 2;
        byte[] password;

        switch ( algorithm )
        {
            case HASH_METHOD_MD5:
            case HASH_METHOD_SMD5:
                return getCredentials( credentials, algoLength, MD5_LENGTH, algorithm );

            case HASH_METHOD_SHA:
            case HASH_METHOD_SSHA:
                return getCredentials( credentials, algoLength, SHA1_LENGTH, algorithm );

            case HASH_METHOD_SHA256:
            case HASH_METHOD_SSHA256:
                return getCredentials( credentials, algoLength, SHA256_LENGTH, algorithm );

            case HASH_METHOD_SHA384:
            case HASH_METHOD_SSHA384:
                return getCredentials( credentials, algoLength, SHA384_LENGTH, algorithm );

            case HASH_METHOD_SHA512:
            case HASH_METHOD_SSHA512:
                return getCredentials( credentials, algoLength, SHA512_LENGTH, algorithm );

            case HASH_METHOD_PKCS5S2:
                return getPbkdf2Credentials( credentials, algoLength, algorithm );

            case HASH_METHOD_CRYPT:
                // The password is associated with a salt. Decompose it
                // in two parts, no decoding required.
                // The salt comes first, not like for SSHA and SMD5, and is 2 bytes long
                // The algorithm, salt, and password will be stored into the PasswordDetails structure.
                byte[] salt = new byte[2];
                password = new byte[credentials.length - salt.length - algoLength];
                split( credentials, algoLength, salt, password );
                return new PasswordDetails( algorithm, salt, password );

            case HASH_METHOD_CRYPT_BCRYPT:
                    salt = Arrays.copyOfRange( credentials, algoLength, credentials.length - 31 );
                    password = Arrays.copyOfRange( credentials, credentials.length - 31, credentials.length );
                    
                    return new PasswordDetails( algorithm, salt, password );
            case HASH_METHOD_CRYPT_MD5:
            case HASH_METHOD_CRYPT_SHA256:
            case HASH_METHOD_CRYPT_SHA512:
                // skip $x$
                algoLength = algoLength + 3;
                return getCryptCredentials( credentials, algoLength, algorithm );

            default:
                // unknown method
                throw new IllegalArgumentException( "Unknown hash algorithm " + algorithm );
        }
    }


    /**
     * Compute the credentials
     */
    private static PasswordDetails getCredentials( byte[] credentials, int algoLength, int hashLen,
        LdapSecurityConstants algorithm )
    {
        // The password is associated with a salt. Decompose it
        // in two parts, after having decoded the password.
        // The salt is at the end of the credentials.
        // The algorithm, salt, and password will be stored into the PasswordDetails structure.
        byte[] passwordAndSalt = Base64
            .decode( Strings.utf8ToString( credentials, algoLength, credentials.length - algoLength ).toCharArray() );

        int saltLength = passwordAndSalt.length - hashLen;
        byte[] salt = saltLength == 0 ? null : new byte[saltLength];
        byte[] password = new byte[hashLen];
        split( passwordAndSalt, 0, password, salt );

        return new PasswordDetails( algorithm, salt, password );
    }


    private static void split( byte[] all, int offset, byte[] left, byte[] right )
    {
        System.arraycopy( all, offset, left, 0, left.length );
        if ( right != null )
        {
            System.arraycopy( all, offset + left.length, right, 0, right.length );
        }
    }


    private static void merge( byte[] all, byte[] left, byte[] right )
    {
        System.arraycopy( left, 0, all, 0, left.length );
        System.arraycopy( right, 0, all, left.length, right.length );
    }


    /**
     * checks if the given password's change time is older than the max age 
     *
     * @param pwdChangedZtime time when the password was last changed
     * @param pwdMaxAgeSec the max age value in seconds
     * @return true if expired, false otherwise
     */
    public static boolean isPwdExpired( String pwdChangedZtime, int pwdMaxAgeSec )
    {
        Date pwdChangeDate = DateUtils.getDate( pwdChangedZtime );

        //DIRSERVER-1735
        long time = pwdMaxAgeSec * 1000L;
        time += pwdChangeDate.getTime();

        Date expiryDate = DateUtils.getDate( DateUtils.getGeneralizedTime( time ) );
        Date now = DateUtils.getDate( DateUtils.getGeneralizedTime() );

        boolean expired = false;

        if ( expiryDate.equals( now ) || expiryDate.before( now ) )
        {
            expired = true;
        }

        return expired;
    }


    /**
     * generates a hash based on the <a href="http://en.wikipedia.org/wiki/PBKDF2">PKCS5S2 spec</a>
     * 
     * Note: this has been implemented to generate hashes compatible with what JIRA generates.
     *       See the <a href="http://pythonhosted.org/passlib/lib/passlib.hash.atlassian_pbkdf2_sha1.html">JIRA's passlib</a>
     * @param credentials the credentials
     * @param algorithm the algorithm to use
     * @param salt the optional salt
     * @return the digested credentials
     */
    private static byte[] generatePbkdf2Hash( byte[] credentials, LdapSecurityConstants algorithm, byte[] salt )
    {
        try
        {
            SecretKeyFactory sk = SecretKeyFactory.getInstance( algorithm.getAlgorithm() );
            char[] password = Strings.utf8ToString( credentials ).toCharArray();
            KeySpec keySpec = new PBEKeySpec( password, salt, 10000, PKCS5S2_LENGTH * 8 );
            Key key = sk.generateSecret( keySpec );
            return key.getEncoded();
        }
        catch ( Exception e )
        {
            throw new RuntimeException( e );
        }
    }


    /**
     * Gets the credentials from a PKCS5S2 hash.
     * The salt for PKCS5S2 hash is prepended to the password
     */
    private static PasswordDetails getPbkdf2Credentials( byte[] credentials, int algoLength, LdapSecurityConstants algorithm )
    {
        // The password is associated with a salt. Decompose it
        // in two parts, after having decoded the password.
        // The salt is at the *beginning* of the credentials, and is 16 bytes long
        // The algorithm, salt, and password will be stored into the PasswordDetails structure.
        byte[] passwordAndSalt = Base64
            .decode( Strings.utf8ToString( credentials, algoLength, credentials.length - algoLength ).toCharArray() );

        int saltLength = passwordAndSalt.length - PKCS5S2_LENGTH;
        byte[] salt = new byte[saltLength];
        byte[] password = new byte[PKCS5S2_LENGTH];

        split( passwordAndSalt, 0, salt, password );

        return new PasswordDetails( algorithm, salt, password );
    }


    private static byte[] generateCryptSalt( int length )
    {
        byte[] salt = new byte[length];
        SecureRandom sr = new SecureRandom();
        for ( int i = 0; i < salt.length; i++ )
        {
            salt[i] = CRYPT_SALT_CHARS[sr.nextInt( CRYPT_SALT_CHARS.length )];
        }
        
        return salt;
    }


    private static PasswordDetails getCryptCredentials( byte[] credentials, int algoLength,
        LdapSecurityConstants algorithm )
    {
        // The password is associated with a salt. Decompose it
        // in two parts, no decoding required.
        // The salt length is dynamic, between the 2nd and 3rd '$'.
        // The algorithm, salt, and password will be stored into the PasswordDetails structure.

        // skip {crypt}$x$
        int pos = algoLength;
        while ( pos < credentials.length )
        {
            if ( credentials[pos] == '$' )
            {
                break;
            }

            pos++;
        }

        byte[] salt = Arrays.copyOfRange( credentials, algoLength, pos );
        byte[] password = Arrays.copyOfRange( credentials, pos + 1, credentials.length );

        return new PasswordDetails( algorithm, salt, password );
    }

}
