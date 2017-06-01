/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.model.message;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.naming.CommunicationException;
import javax.naming.LimitExceededException;
import javax.naming.PartialResultException;
import javax.naming.SizeLimitExceededException;

import org.apache.directory.api.ldap.model.exception.LdapAdminLimitExceededException;
import org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException;
import org.apache.directory.api.ldap.model.exception.LdapAliasDereferencingException;
import org.apache.directory.api.ldap.model.exception.LdapAliasException;
import org.apache.directory.api.ldap.model.exception.LdapAttributeInUseException;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationNotSupportedException;
import org.apache.directory.api.ldap.model.exception.LdapCannotCancelException;
import org.apache.directory.api.ldap.model.exception.LdapContextNotEmptyException;
import org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeTypeException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException;
import org.apache.directory.api.ldap.model.exception.LdapLoopDetectedException;
import org.apache.directory.api.ldap.model.exception.LdapNoPermissionException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOperationErrorException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.exception.LdapProtocolErrorException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaViolationException;
import org.apache.directory.api.ldap.model.exception.LdapServiceUnavailableException;
import org.apache.directory.api.ldap.model.exception.LdapSizeLimitExceededException;
import org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException;
import org.apache.directory.api.ldap.model.exception.LdapTimeLimitExceededException;
import org.apache.directory.api.ldap.model.exception.LdapTooLateException;
import org.apache.directory.api.ldap.model.exception.LdapUnknownException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;


/**
 * Type safe LDAP message envelope result code enumeration. The resultCode is a
 * parameter of the LDAPResult which is the construct used in this protocol to
 * return success or failure indications from servers to clients. In response to
 * various requests servers will return responses containing fields of type
 * LDAPResult to indicate the final status of a protocol operation request. This
 * enumeration represents the various status codes associated with an
 * LDAPResult, hence it is called the ResultCodeEnum. Here are the definitions
 * and values for error codes from section 4.1.10 of <a
 * href="http://www.faqs.org/rfcs/rfc2251.html">RFC 2251</a>:
 * 
 * <pre><code>
 *     resultCode
 *        ENUMERATED {
 *           success                      (0),
 *           operationsError              (1),
 *           protocolError                (2),
 *           timeLimitExceeded            (3),
 *           sizeLimitExceeded            (4),
 *           compareFalse                 (5),
 *           compareTrue                  (6),
 *           authMethodNotSupported       (7),
 *           strongAuthRequired           (8),
 *           partialResults               (9),   -- new
 *           referral                     (10),  -- new
 *           adminLimitExceeded           (11),  -- new
 *           unavailableCriticalExtension (12),  -- new
 *           confidentialityRequired      (13),  -- new
 *           saslBindInProgress           (14),  -- new
 *           noSuchAttribute              (16),
 *           undefinedAttributeType       (17),
 *           inappropriateMatching        (18),
 *           constraintViolation          (19),
 *           attributeOrValueExists       (20),
 *           invalidAttributeSyntax       (21),
 *           -- 22-31 unused --
 *           NO_SUCH_OBJECT               (32),
 *           aliasProblem                 (33),
 *           invalidDNSyntax              (34),
 *           -- 35 reserved for undefined isLeaf --
 *           aliasDereferencingProblem    (36),
 *           -- 37-47 unused --
 *           inappropriateAuthentication  (48),
 *           invalidCredentials           (49),
 *           insufficientAccessRights     (50),
 *           busy                         (51),
 *           unavailable                  (52),
 *           unwillingToPerform           (53),
 *           loopDetect                   (54),
 *           -- 55-63 unused --
 *           namingViolation              (64),
 *           objectClassViolation         (65),
 *           notAllowedOnNonLeaf          (66),
 *           notAllowedOnRDN              (67),
 *           entryAlreadyExists           (68),
 *           objectClassModsProhibited    (69),
 *           -- 70 reserved for CLDAP --
 *           affectsMultipleDSAs          (71), -- new
 *           -- 72-79 unused --
 *           other                        (80) },
 *           -- 81-90 reserved for APIs --
 * </code></pre>
 * 
 * All the result codes with the exception of success, compareFalse and
 * compareTrue are to be treated as meaning the operation could not be completed
 * in its entirety. Most of the result codes are based on problem indications
 * from X.511 error data types. Result codes from 16 to 21 indicate an
 * AttributeProblem, codes 32, 33, 34 and 36 indicate a NameProblem, codes 48,
 * 49 and 50 indicate a SecurityProblem, codes 51 to 54 indicate a
 * ServiceProblem, and codes 64 to 69 and 71 indicates an UpdateProblem. If a
 * client receives a result code which is not listed above, it is to be treated
 * as an unknown error condition. The majority of this javadoc was pasted in
 * from RFC 2251. There's and expired draft out there on error codes which makes
 * alot of sense: <a
 * href="http://www.alternic.org/drafts/drafts-j-k/draft-just-ldapv3-rescodes-02.html"> 
 * ietf (expired) draft</a> on error codes (read at your discretion).
 * Result codes have been identified and split into categories:
 * <ul>
 * <li> Non-Erroneous: Five result codes that may be returned in LDAPResult are
 * not used to indicate an error. </li>
 * <li> General: returned only when no suitable specific error exists. </li>
 * <li> Specific: Specific errors are used to indicate that a particular type of
 * error has occurred. These error types are:
 * <ul>
 * <li> Name, </li>
 * <li> Update, </li>
 * <li> Attribute </li>
 * <li> Security, and </li>
 * <li> Service </li>
 * </ul>
 * </li>
 * </ul>
 * The result codes are also grouped according to the following LDAP operations
 * which return responses:
 * <ul>
 * <li> bind </li>
 * <li> search </li>
 * <li> modify </li>
 * <li> modifyDn </li>
 * <li> add </li>
 * <li> delete </li>
 * <li> compare </li>
 * <li> extended </li>
 * </ul>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum ResultCodeEnum
{
    // ------------------------------------------------------------------------
    // Public Static Constants: Enumeration values and names.
    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // Non Erroneous Codes:
    //
    // Five result codes that may be returned in LDAPResult are not used to
    // indicate an error. These result codes are listed below. The first
    // three codes, indicate to the client that no further action is required
    // in order to satisfy their request. In contrast, the last two errors
    // require further action by the client in order to complete their original
    // operation request.
    // ------------------------------------------------------------------------

    /**
     * It is returned when the client operation completed successfully without
     * errors. This code is one of 5 result codes that may be returned in the
     * LDAPResult which are not used to indicate an error. Applicable
     * operations: all except for Compare. Result code type: Non-Erroneous
     */
    SUCCESS(0, "success"),

    /**
     * Servers sends this result code to LDAP v2 clients to refer them to
     * another LDAP server. When sending this code to a client, the server
     * includes a newline-delimited list of LDAP URLs that identify another LDAP
     * server. If the client identifies itself as an LDAP v3 client in the
     * request, servers send an REFERRAL result code instead of this result
     * code.
     */
    PARTIAL_RESULTS(9, "partialResults"),

    /**
     * It is used to indicate that the result of a Compare operation is FALSE
     * and does not indicate an error. 1 of 5 codes that do not indicate an
     * error condition. Applicable operations: Compare. Result code type:
     * Non-Erroneous
     */
    COMPARE_FALSE(5, "compareFalse"),

    /**
     * It is used to indicate that the result of a Compare operation is TRUE and
     * does not indicate an error. 1 of 5 codes that do not indicate an error
     * condition. Applicable operations: Compare. Result code type:
     * Non-Erroneous
     */
    COMPARE_TRUE(6, "compareTrue"),

    /**
     * Rather than indicating an error, this result code is used to indicate
     * that the server does not hold the target entry of the request but is able
     * to provide alternative servers that may. A set of server(s) URLs may be
     * returned in the referral field, which the client may subsequently query
     * to attempt to complete their operation. 1 of 5 codes that do not indicate
     * an error condition yet requires further action on behalf of the client to
     * complete the request. This result code is new in LDAPv3. Applicable
     * operations: all. Result code type: Non-Erroneous
     */
    REFERRAL(10, "referral"),

    /**
     * This result code is not an error response from the server, but rather, is
     * a request for bind continuation. The server requires the client to send a
     * new bind request, with the same SASL mechanism, to continue the
     * authentication process [RFC2251, Section 4.2.3]. This result code is new
     * in LDAPv3. Applicable operations: Bind. Result code type: Non-Erroneous
     */
    SASL_BIND_IN_PROGRESS(14, "saslBindInProgress"),

    // ------------------------------------------------------------------------
    // Problem Specific Error Codes:
    //
    // Specific errors are used to indicate that a particular type of error
    // has occurred. These error types are Name, Update, Attribute, Security,
    // and Service.
    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // Security Problem Specific Error Codes:
    //
    // A security error reports a problem in carrying out an operation for
    // security reasons [X511, Section 12.7].
    // ------------------------------------------------------------------------

    /**
     * This error code should be returned if the client requests, in a Bind
     * request, an authentication method which is not supported or recognized by
     * the server. Applicable operations: Bind. Result code type: Specific
     * (Security)
     */
    AUTH_METHOD_NOT_SUPPORTED(7, "authMethodNotSupported"),

    /**
     * This error may be returned on a bind request if the server only accepts
     * strong authentication or it may be returned when a client attempts an
     * operation which requires the client to be strongly authenticated - for
     * example Delete. This result code may also be returned in an unsolicited
     * notice of disconnection if the server detects that an established
     * underlying security association protecting communication between the
     * client and server has unexpectedly failed or been compromised. [RFC2251,
     * Section 4.4.1] Applicable operations: all. Result code type: Specific
     * (Security)
     */
    STRONG_AUTH_REQUIRED(8, "strongAuthRequired"),

    /**
     * This error code may be returned if the session is not protected by a
     * protocol which provides session confidentiality. For example, if the
     * client did not establish a TLS connection using a cipher suite which
     * provides confidentiality of the session before sending any other
     * requests, and the server requires session confidentiality then the server
     * may reject that request with a result code of confidentialityRequired.
     * This error code is new in LDAPv3. Applicable operations: all. Result code
     * type: Specific (Security)
     */
    CONFIDENTIALITY_REQUIRED(13, "confidentialityRequired"),

    /**
     * An alias was encountered in a situation where it was not allowed or where
     * access was denied [X511, Section 12.5]. For example, if the client does
     * not have read permission for the aliasedObjectName attribute and its
     * value then the error aliasDereferencingProblem should be returned. [X511,
     * Section 7.11.1.1] Notice that this error has similar meaning to
     * INSUFFICIENT_ACCESS_RIGHTS (50), but is specific to Searching on an alias.
     * Applicable operations: Search. Result code type: Specific (Security)
     */
    ALIAS_DEREFERENCING_PROBLEM(36, "aliasDereferencingProblem"),

    /**
     * This error should be returned by the server when the client has tried to
     * use a method of authentication that is inappropriate, that is a method of
     * authentication which the client is unable to use correctly. In other
     * words, the level of security associated with the requestor's credentials
     * is inconsistent with the level of protection requested, e.g. simple
     * credentials were supplied while strong credentials were required [X511,
     * Section 12.7]. Applicable operations: Bind. Result code type: Specific
     * (Security)
     */
    INAPPROPRIATE_AUTHENTICATION(48, "inappropriateAuthentication"),

    /**
     * This error code is returned if the Dn or password used in a simple bind
     * operation is incorrect, or if the Dn or password is incorrect for some
     * other reason, e.g. the password has expired. This result code only
     * applies to Bind operations -- it should not be returned for other
     * operations if the client does not have sufficient permission to perform
     * the requested operation - in this case the return code should be
     * insufficientAccessRights. Applicable operations: Bind. Result code type:
     * Specific (Security)
     */
    INVALID_CREDENTIALS(49, "invalidCredentials"),

    /**
     * The requestor does not have the right to carry out the requested
     * operation [X511, Section 12.7]. Note that the more specific
     * aliasDereferencingProblem is returned in case of a Search on an alias
     * where the requestor has insufficientAccessRights. Applicable operations:
     * all except for Bind. Result code type: Specific (Security)
     */
    INSUFFICIENT_ACCESS_RIGHTS(50, "insufficientAccessRights"),

    // ------------------------------------------------------------------------
    // Service Problem Specific Error Codes:
    //
    // A service error reports a problem related to the provision of the
    // service [X511, Section 12.8].
    // ------------------------------------------------------------------------

    /**
     * If the server requires that the client bind before browsing or modifying
     * the directory, the server MAY reject a request other than binding,
     * unbinding or an extended request with the "operationsError" result.
     * [RFC2251, Section 4.2.1] Applicable operations: all except Bind. Result
     * code type: Specific (Service)
     */
    OPERATIONS_ERROR(1, "operationsError"),

    /**
     * A protocol error should be returned by the server when an invalid or
     * malformed request is received from the client. This may be a request that
     * is not recognized as an LDAP request, for example, if a nonexistent
     * operation were specified in LDAPMessage. As well, it may be the result of
     * a request that is missing a required parameter, such as a search filter
     * in a search request. If the server can return an error, which is more
     * specific than protocolError, then this error should be returned instead.
     * For example if the server does not recognize the authentication method
     * requested by the client then the error authMethodNotSupported should be
     * returned instead of protocolError. The server may return details of the
     * error in the error string. Applicable operations: all. Result code type:
     * Specific (Service)
     */
    PROTOCOL_ERROR(2, "protocolError"),

    /**
     * This error should be returned when the time to perform an operation has
     * exceeded either the time limit specified by the client (which may only be
     * set by the client in a search operation) or the limit specified by the
     * server. If the time limit is exceeded on a search operation then the
     * result is an arbitrary selection of the accumulated results [X511,
     * Section 7.5]. Note that an arbitrary selection of results may mean that
     * no results are returned to the client. If the LDAP server is a front end
     * for an X.500 server, any operation that is chained may exceed the
     * timelimit, therefore clients can expect to receive timelimitExceeded for
     * all operations. For stand alone LDAP- Servers that do not implement
     * chaining it is unlikely that operations other than search operations will
     * exceed the defined timelimit. Applicable operations: all. Result code
     * type: Specific (Service)
     */
    TIME_LIMIT_EXCEEDED(3, "timeLimitExceeded"),

    /**
     * This error should be returned when the number of results generated by a
     * search exceeds the maximum number of results specified by either the
     * client or the server. If the size limit is exceeded then the results of a
     * search operation will be an arbitrary selection of the accumulated
     * results, equal in number to the size limit [X511, Section 7.5].
     * Applicable operations: Search. Result code type: Specific (Service)
     */
    SIZE_LIMIT_EXCEEDED(4, "sizeLimitExceeded"),

    /**
     * The server has reached some limit set by an administrative authority, and
     * no partial results are available to return to the user [X511, Section
     * 12.8]. For example, there may be an administrative limit to the number of
     * entries a server will check when gathering potential search result
     * candidates [Net]. This error code is new in LDAPv3. Applicable
     * operations: all. Result code type: Specific (Service)
     */
    ADMIN_LIMIT_EXCEEDED(11, "adminLimitExceeded"),

    /**
     * The server was unable to satisfy the request because one or more critical
     * extensions were not available [X511, Section 12.8]. This error is
     * returned, for example, when a control submitted with a request is marked
     * critical but is not recognized by a server or when such a control is not
     * appropriate for the operation type. [RFC2251 section 4.1.12]. This error
     * code is new in LDAPv3. Applicable operations: all. Result code type:
     * Specific (Service)
     */
    UNAVAILABLE_CRITICAL_EXTENSION(12, "unavailableCriticalExtension"),

    /**
     * This error code may be returned if the server is unable to process the
     * client's request at this time. This implies that if the client retries
     * the request shortly the server will be able to process it then.
     * Applicable operations: all. Result code type: Specific (Service)
     */
    BUSY(51, "busy"),

    /**
     * This error code is returned when the server is unavailable to process the
     * client's request. This usually means that the LDAP server is shutting
     * down [RFC2251, Section 4.2.3]. Applicable operations: all. Result code
     * type: Specific (Service)
     */
    UNAVAILABLE(52, "unavailable"),

    /**
     * This error code should be returned by the server when a client request is
     * properly formed but which the server is unable to complete due to
     * server-defined restrictions. For example, the server, or some part of it,
     * is not prepared to execute this request, e.g. because it would lead to
     * excessive consumption of resources or violates the policy of an
     * Administrative Authority involved [X511, Section 12.8]. If the server is
     * able to return a more specific error code such as adminLimitExceeded it
     * should. This error may also be returned if the client attempts to modify
     * attributes which can not be modified by users, e.g., operational
     * attributes such as creatorsName or createTimestamp [X511, Section 7.12].
     * If appropriate, details of the error should be provided in the error
     * message. Applicable operations: all. Result code type: Specific (Service)
     */
    UNWILLING_TO_PERFORM(53, "unwillingToPerform"),

    /**
     * This error may be returned by the server if it detects an alias or
     * referral loop, and is unable to satisfy the client's request. Applicable
     * operations: all. Result code type: Specific (Service)
     */
    LOOP_DETECT(54, "loopDetect"),

    // ------------------------------------------------------------------------
    // Attribute Problem Specific Error Codes:
    //
    // An attribute error reports a problem related to an attribute specified
    // by the client in their request message.
    // ------------------------------------------------------------------------

    /**
     * This error may be returned if the attribute specified as an argument of
     * the operation does not exist in the entry. Applicable operations: Modify,
     * Compare. Result code type: Specific (Attribute)
     */
    NO_SUCH_ATTRIBUTE(16, "noSuchAttribute"),

    /**
     * This error may be returned if the specified attribute is unrecognized by
     * the server, since it is not present in the server's defined schema. If
     * the server doesn't recognize an attribute specified in a search request
     * as the attribute to be returned the server should not return an error in
     * this case - it should just return values for the requested attributes it
     * does recognize. Note that this result code only applies to the Add and
     * Modify operations [X.511, Section 12.4]. Applicable operations: Modify,
     * Add. Result code type: Specific (Attribute)
     */
    UNDEFINED_ATTRIBUTE_TYPE(17, "undefinedAttributeType"),

    /**
     * An attempt was made, e.g., in a filter, to use a matching rule not
     * defined for the attribute type concerned [X511, Section 12.4]. Applicable
     * operations: Search. Result code type: Specific (Attribute)
     */
    INAPPROPRIATE_MATCHING(18, "inappropriateMatching"),

    /**
     * This error should be returned by the server if an attribute value
     * specified by the client violates the constraints placed on the attribute
     * as it was defined in the DSA - this may be a size constraint or a
     * constraint on the content. Applicable operations: Modify, Add, ModifyDN.
     * Result code type: Specific (Attribute)
     */
    CONSTRAINT_VIOLATION(19, "constraintViolation"),

    /**
     * This error should be returned by the server if the value specified by the
     * client already exists within the attribute. Applicable operations:
     * Modify, Add. Result code type: Specific (Attribute)
     */
    ATTRIBUTE_OR_VALUE_EXISTS(20, "attributeOrValueExists"),

    /**
     * This error should be returned by the server if the attribute syntax for
     * the attribute value, specified as an argument of the operation, is
     * unrecognized or invalid. Applicable operations: Modify, Add. Result code
     * type: Specific (Attribute)
     */
    INVALID_ATTRIBUTE_SYNTAX(21, "invalidAttributeSyntax"),

    // ------------------------------------------------------------------------
    // Name Problem Specific Error Codes:
    //
    // A name error reports a problem related to the distinguished name
    // provided as an argument to an operation [X511, Section 12.5].
    //
    // For result codes of noSuchObject, aliasProblem, invalidDNSyntax and
    // aliasDereferencingProblem (see Section 5.2.2.3.7), the matchedDN
    // field is set to the name of the lowest entry (object or alias) in the
    // directory that was matched. If no aliases were dereferenced while
    // attempting to locate the entry, this will be a truncated form of the
    // name provided, or if aliases were dereferenced, of the resulting
    // name, as defined in section 12.5 of X.511 [X511]. The matchedDN field
    // is to be set to a zero length string with all other result codes
    // [RFC2251, Section 4.1.10].
    // ------------------------------------------------------------------------

    /**
     * This error should only be returned if the target object cannot be found.
     * For example, in a search operation if the search base can not be located
     * in the DSA the server should return NO_SUCH_OBJECT. If, however, the search
     * base is found but does not match the search filter, success, with no
     * resultant objects, should be returned instead of NO_SUCH_OBJECT. If the
     * LDAP server is a front end for an X.500 DSA then NO_SUCH_OBJECT may also be
     * returned if discloseOnError is not granted for an entry and the client
     * does not have permission to view or modify the entry. Applicable
     * operations: all except for Bind. Result code type: Specific (Name)
     */
    NO_SUCH_OBJECT(32, "noSuchObject"),

    /**
     * An alias has been dereferenced which names no object [X511, Section 12.5]
     * Applicable operations: Search. Result code type: Specific (Name)
     */
    ALIAS_PROBLEM(33, "aliasProblem"),

    /**
     * This error should be returned by the server if the Dn syntax is
     * incorrect. It should not be returned if the Dn is correctly formed but
     * represents an entry which is not permitted by the structure rules at the
     * DSA ; in this case namingViolation should be returned instead. Applicable
     * operations: all. Result code type: Specific (Name)
     */
    INVALID_DN_SYNTAX(34, "invalidDNSyntax"),

    // ------------------------------------------------------------------------
    // Update Problem Specific Error Codes:
    //
    // An update error reports problems related to attempts to add, delete, or
    // modify information in the DIB [X511, Section 12.9].
    // ------------------------------------------------------------------------

    /**
     * The attempted addition or modification would violate the structure rules
     * of the DIT as defined in the directory schema and X.501. That is, it
     * would place an entry as the subordinate of an alias entry, or in a region
     * of the DIT not permitted to a member of its object class, or would define
     * an Rdn for an entry to include a forbidden attribute type [X511, Section
     * 12.9]. Applicable operations: Add, ModifyDN. Result code type: Specific
     * (Update)
     */
    NAMING_VIOLATION(64, "namingViolation"),

    /**
     * This error should be returned if the operation requested by the user
     * would violate the objectClass requirements for the entry if carried out.
     * On an add or modify operation this would result from trying to add an
     * object class without a required attribute, or by trying to add an
     * attribute which is not permitted by the current object class set in the
     * entry. On a modify operation this may result from trying to remove a
     * required attribute without removing the associated auxiliary object
     * class, or by attempting to remove an object class while the attributes it
     * permits are still present. Applicable operations: Add, Modify, ModifyDN.
     * Result code type: Specific (Update)
     */
    OBJECT_CLASS_VIOLATION(65, "objectClassViolation"),

    /**
     * This error should be returned if the client attempts to perform an
     * operation which is permitted only on leaf entries - e.g., if the client
     * attempts to delete a non-leaf entry. If the directory does not permit
     * ModifyDN for non-leaf entries then this error may be returned if the
     * client attempts to change the Dn of a non-leaf entry. (Note that 1988
     * edition X.500 servers only permitted change of the Rdn of an entry's Dn
     * [X.511, Section 11.4.1]). Applicable operations: Delete, ModifyDN. Result
     * code type: Specific (Update)
     */
    NOT_ALLOWED_ON_NON_LEAF(66, "notAllowedOnNonLeaf"),

    /**
     * The attempted operation would affect the Rdn (e.g., removal of an
     * attribute which is a part of the Rdn) [X511, Section 12.9]. If the client
     * attempts to remove from an entry any of its distinguished values, those
     * values which form the entry's relative distinguished name the server
     * should return the error notAllowedOnRDN. [RFC2251, Section 4.6]
     * Applicable operations: Modify. Result code type: Specific (Update)
     */
    NOT_ALLOWED_ON_RDN(67, "notAllowedOnRDN"),

    /**
     * This error should be returned by the server when the client attempts to
     * add an entry which already exists, or if the client attempts to rename an
     * entry with the name of an entry which exists. Applicable operations: Add,
     * ModifyDN. Result code type: Specific (Update)
     */
    ENTRY_ALREADY_EXISTS(68, "entryAlreadyExists"),

    /**
     * An operation attempted to modify an object class that should not be
     * modified, e.g., the structural object class of an entry. Some servers may
     * not permit object class modifications, especially modifications to the
     * structural object class since this may change the entry entirely, name
     * forms, structure rules etc. [X.511, Section 12.9]. Applicable operations:
     * Modify. Result code type: Specific (Update)
     */
    OBJECT_CLASS_MODS_PROHIBITED(69, "objectClassModsProhibited"),

    /**
     * This error code should be returned to indicate that the operation could
     * not be performed since it affects more than one DSA. This error code is
     * new for LDAPv3. X.500 restricts the ModifyDN operation to only affect
     * entries that are contained within a single server. If the LDAP server is
     * mapped onto DAP, then this restriction will apply, and the resultCode
     * affectsMultipleDSAs will be returned if this error occurred. In general
     * clients MUST NOT expect to be able to perform arbitrary movements of
     * entries and subtrees between servers [RFC2251, Section 4.9]. Applicable
     * operations: ModifyDN. Result code type: Specific (Update)
     */
    AFFECTS_MULTIPLE_DSAS(71, "affectsMultipleDSAs"),

    // ------------------------------------------------------------------------
    // General Error Codes:
    //
    // A general error code typically specifies an error condition for which
    // there is no suitable specific error code. If the server can return an
    // error, which is more specific than the following general errors, then
    // the specific error should be returned instead.
    // ------------------------------------------------------------------------

    /**
     * This error code should be returned only if no other error code is
     * suitable. Use of this error code should be avoided if possible. Details
     * of the error should be provided in the error message. Applicable
     * operations: all. Result code type: General
     */
    OTHER(80, "other"),

    /**
     * This error code is returned when an operation has been canceled using
     * the Cancel extended operation. 
     */
    CANCELED(118, "canceled"),

    /**
     * This error code is returned if the server has no knowledge of
     * the operation requested for cancelation.
     */
    NO_SUCH_OPERATION(119, "noSuchOperation"),

    /**
     * The tooLate resultCode is returned to indicate that it is too late to
     * cancel the outstanding operation.  For example, the server may return
     * tooLate for a request to cancel an outstanding modify operation which
     * has already committed updates to the underlying data store.
     */
    TOO_LATE(120, "tooLate"),

    /**
     * The cannotCancel resultCode is returned if the identified operation
     * does not support cancelation or the cancel operation could not be
     * performed.  The following classes of operations are not cancelable:
     *
     * -  operations which have no response,
     *
     * -  operations which create, alter, or destroy authentication and/or
     *    authorization associations,
     *
     * -  operations which establish, alter, or tear-down security services,
     *    and
     *
     * -  operations which abandon or cancel other operations.
     */
    CANNOT_CANCEL(121, "cannotCancel"),

    /**
     * The server may return this result code on the initial content poll
     * if it is safe to do so when it is unable to perform the operation
     * due to various reasons. For more detailed explanation refer 
     * <a href="http://www.faqs.org/rfcs/rfc4533.html">RFC 4533 (a.k.a syncrepl)</a>
     */
    E_SYNC_REFRESH_REQUIRED(4096, "eSyncRefreshRequired"),

    /**
     * A unknown result code to cover all the other cases
     */
    // -- 15 unused --
    // -- 22-31 unused --
    // -- 35 reserved for undefined isLeaf --
    // -- 37-47 unused --
    // -- 55-63 unused --
    // -- 70 reserved for CLDAP --
    // -- 72-79 unused --
    // -- 81-90 reserved for APIs --
    UNKNOWN(122, "unknown");

    /** Stores the integer value of each element of the enumeration */
    private int value;

    /** Stores the description of each element of the enumeration */
    private String message;

    private static final Set<ResultCodeEnum> EMPTY_RESULT_CODE_SET = new HashSet<>();

    // ------------------------------------------------------------------------
    // Error Codes Grouped Into Categories & Static Accessors
    // ------------------------------------------------------------------------

    /**
     * Five result codes that may be returned in LDAPResult are not used to
     * indicate an error. The first three codes, indicate to the client that no
     * further action is required in order to satisfy their request. In
     * contrast, the last two errors require further action by the client in
     * order to complete their original operation request. The set contains:
     * <ul>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#COMPARETRUE">COMPARETRUE</a></li>
     * <li><a href="#COMPAREFALSE">COMPAREFALSE</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#SASL_BIND_IN_PROGRESS">SASL_BIND_IN_PROGRESS</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> NON_ERRONEOUS_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.COMPARE_TRUE );
        set.add( ResultCodeEnum.COMPARE_FALSE );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.SASL_BIND_IN_PROGRESS );
        set.add( ResultCodeEnum.CANCELED );
        NON_ERRONEOUS_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that may result from bind operations.
     * The set contains:
     * <ul>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#SASL_BIND_IN_PROGRESS">SASL_BIND_IN_PROGRESS</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#INVALID_CREDENTIALS">INVALID_CREDENTIALS</a></li>
     * <li><a href="#AUTH_METHOD_NOT_SUPPORTED">AUTH_METHOD_NOT_SUPPORTED</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#INAPPROPRIATE_AUTHENTICATION">INAPPROPRIATE_AUTHENTICATION</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> BIND_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.SASL_BIND_IN_PROGRESS );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.INVALID_CREDENTIALS );
        set.add( ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INAPPROPRIATE_AUTHENTICATION );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CANCELED );
        BIND_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that may result from search operations.
     * The set contains:
     * <ul>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#ALIAS_PROBLEM">ALIAS_PROBLEM</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#SIZE_LIMIT_EXCEEDED">SIZE_LIMIT_EXCEEDED</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#INAPPROPRIATE_MATCHING">INAPPROPRIATE_MATCHING</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#ALIAS_DEREFERENCING_PROBLEM">ALIAS_DEREFERENCING_PROBLEM</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> SEARCH_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.ALIAS_PROBLEM );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.SIZE_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.INAPPROPRIATE_MATCHING );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.ALIAS_DEREFERENCING_PROBLEM );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CANCELED );
        set.add( ResultCodeEnum.E_SYNC_REFRESH_REQUIRED );
        SEARCH_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that may result from modify operations.
     * The set contains:
     * <ul>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#NOT_ALLOWED_ON_RDN">NOT_ALLOWED_ON_RDN</a></li>
     * <li><a href="#NO_SUCH_ATTRIBUTE">NO_SUCH_ATTRIBUTE</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#CONSTRAINT_VIOLATION">CONSTRAINT_VIOLATION</a></li>
     * <li><a href="#OBJECT_CLASS_VIOLATION">OBJECT_CLASS_VIOLATION</a></li>
     * <li><a href="#INVALID_ATTRIBUTE_SYNTAX">INVALID_ATTRIBUTE_SYNTAX</a></li>
     * <li><a href="#UNDEFINED_ATTRIBUTE_TYPE">UNDEFINED_ATTRIBUTE_TYPE</a></li>
     * <li><a href="#ATTRIBUTE_OR_VALUE_EXISTS">ATTRIBUTE_OR_VALUE_EXISTS</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#OBJECT_CLASS_MODS_PROHIBITED">OBJECT_CLASS_MODS_PROHIBITED</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> MODIFY_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.NOT_ALLOWED_ON_RDN );
        set.add( ResultCodeEnum.NO_SUCH_ATTRIBUTE );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.CONSTRAINT_VIOLATION );
        set.add( ResultCodeEnum.OBJECT_CLASS_VIOLATION );
        set.add( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX );
        set.add( ResultCodeEnum.UNDEFINED_ATTRIBUTE_TYPE );
        set.add( ResultCodeEnum.ATTRIBUTE_OR_VALUE_EXISTS );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.OBJECT_CLASS_MODS_PROHIBITED );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CANCELED );
        MODIFY_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that may result from add operations.
     * The set contains:
     * <ul>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#NAMING_VIOLATION">NAMING_VIOLATION</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#ENTRY_ALREADY_EXISTS">ENTRY_ALREADY_EXISTS</a></li>
     * <li><a href="#CONSTRAINT_VIOLATION">CONSTRAINT_VIOLATION</a></li>
     * <li><a href="#OBJECT_CLASS_VIOLATION">OBJECT_CLASS_VIOLATION</a></li>
     * <li><a href="#INVALID_ATTRIBUTE_SYNTAX">INVALID_ATTRIBUTE_SYNTAX</a></li>
     * <li><a href="#ATTRIBUTE_OR_VALUE_EXISTS">ATTRIBUTE_OR_VALUE_EXISTS</a></li>
     * <li><a href="#UNDEFINED_ATTRIBUTE_TYPE">UNDEFINED_ATTRIBUTE_TYPE</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> ADD_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.NAMING_VIOLATION );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.ENTRY_ALREADY_EXISTS );
        set.add( ResultCodeEnum.CONSTRAINT_VIOLATION );
        set.add( ResultCodeEnum.OBJECT_CLASS_VIOLATION );
        set.add( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX );
        set.add( ResultCodeEnum.ATTRIBUTE_OR_VALUE_EXISTS );
        set.add( ResultCodeEnum.UNDEFINED_ATTRIBUTE_TYPE );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CANCELED );
        ADD_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that may result from delete operations.
     * The set may contain:
     * <ul>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#NOT_ALLOWED_ON_NON_LEAF">NOT_ALLOWED_ON_NON_LEAF</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> DELETE_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.NOT_ALLOWED_ON_NON_LEAF );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CANCELED );
        DELETE_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations resulting from modifyDn operations. The
     * set contains:
     * <ul>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#NAMING_VIOLATION">NAMING_VIOLATION</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#ENTRY_ALREADY_EXISTS">ENTRY_ALREADY_EXISTS</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#NOT_ALLOWED_ON_NON_LEAF">NOT_ALLOWED_ON_NON_LEAF</a></li>
     * <li><a href="#AFFECTS_MULTIPLE_DSAS">AFFECTS_MULTIPLE_DSAS</a></li>
     * <li><a href="#CONSTRAINT_VIOLATION">CONSTRAINT_VIOLATION</a></li>
     * <li><a href="#OBJECT_CLASS_VIOLATION">OBJECT_CLASS_VIOLATION</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> MODIFYDN_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.NAMING_VIOLATION );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.ENTRY_ALREADY_EXISTS );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.NOT_ALLOWED_ON_NON_LEAF );
        set.add( ResultCodeEnum.AFFECTS_MULTIPLE_DSAS );
        set.add( ResultCodeEnum.CONSTRAINT_VIOLATION );
        set.add( ResultCodeEnum.OBJECT_CLASS_VIOLATION );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CANCELED );
        MODIFYDN_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that may result from compare
     * operations. The set contains:
     * <ul>
     * <li><a href="#OPERATIONSERROR">OPERATIONSERROR</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#COMPAREFALSE">COMPAREFALSE</a></li>
     * <li><a href="#COMPARETRUE">COMPARETRUE</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#NO_SUCH_ATTRIBUTE">NO_SUCH_ATTRIBUTE</a></li>
     * <li><a href="#INVALID_ATTRIBUTE_SYNTAX">INVALID_ATTRIBUTE_SYNTAX</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> COMPARE_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.OPERATIONS_ERROR );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.COMPARE_FALSE );
        set.add( ResultCodeEnum.COMPARE_TRUE );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.NO_SUCH_ATTRIBUTE );
        set.add( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.CANCELED );
        COMPARE_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of result code enumerations that could result from extended
     * operations. The set contains:
     * <ul>
     * <li></li>
     * <li><a href="#SUCCESS">SUCCESS</a></li>
     * <li><a href="#OPERATIONSERROR">OPERATIONSERROR</a></li>
     * <li><a href="#PROTOCOL_ERROR">PROTOCOL_ERROR</a></li>
     * <li><a href="#TIME_LIMIT_EXCEEDED">TIME_LIMIT_EXCEEDED</a></li>
     * <li><a href="#SIZE_LIMIT_EXCEEDED">SIZE_LIMIT_EXCEEDED</a></li>
     * <li><a href="#COMPAREFALSE">COMPAREFALSE</a></li>
     * <li><a href="#COMPARETRUE">COMPARETRUE</a></li>
     * <li><a href="#AUTH_METHOD_NOT_SUPPORTED">AUTH_METHOD_NOT_SUPPORTED</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">STRONG_AUTH_REQUIRED</a></li>
     * <li><a href="#REFERRAL">REFERRAL</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">ADMIN_LIMIT_EXCEEDED</a></li>
     * <li><a href="#UNAVAILABLE_CRITICAL_EXTENSION">UNAVAILABLE_CRITICAL_EXTENSION</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">CONFIDENTIALITY_REQUIRED</a></li>
     * <li><a href="#SASL_BIND_IN_PROGRESS">SASL_BIND_IN_PROGRESS</a></li>
     * <li><a href="#NO_SUCH_ATTRIBUTE">NO_SUCH_ATTRIBUTE</a></li>
     * <li><a href="#UNDEFINED_ATTRIBUTE_TYPE">UNDEFINED_ATTRIBUTE_TYPE</a></li>
     * <li><a href="#INAPPROPRIATE_MATCHING">INAPPROPRIATE_MATCHING</a></li>
     * <li><a href="#CONSTRAINT_VIOLATION">CONSTRAINT_VIOLATION</a></li>
     * <li><a href="#ATTRIBUTE_OR_VALUE_EXISTS">ATTRIBUTE_OR_VALUE_EXISTS</a></li>
     * <li><a href="#INVALID_ATTRIBUTE_SYNTAX">INVALID_ATTRIBUTE_SYNTAX</a></li>
     * <li><a href="#NO_SUCH_OBJECT">NO_SUCH_OBJECT</a></li>
     * <li><a href="#ALIAS_PROBLEM">ALIAS_PROBLEM</a></li>
     * <li><a href="#INVALID_DN_SYNTAX">INVALID_DN_SYNTAX</a></li>
     * <li><a href="#ALIAS_DEREFERENCING_PROBLEM">ALIAS_DEREFERENCING_PROBLEM</a></li>
     * <li><a href="#INAPPROPRIATE_AUTHENTICATION">INAPPROPRIATE_AUTHENTICATION</a></li>
     * <li><a href="#INVALID_CREDENTIALS">INVALID_CREDENTIALS</a></li>
     * <li><a href="#INSUFFICIENT_ACCESS_RIGHTS">INSUFFICIENT_ACCESS_RIGHTS</a></li>
     * <li><a href="#BUSY">BUSY</a></li>
     * <li><a href="#UNAVAILABLE">UNAVAILABLE</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">UNWILLING_TO_PERFORM</a></li>
     * <li><a href="#LOOP_DETECT">LOOP_DETECT</a></li>
     * <li><a href="#NAMING_VIOLATION">NAMING_VIOLATION</a></li>
     * <li><a href="#OBJECT_CLASS_VIOLATION">OBJECT_CLASS_VIOLATION</a></li>
     * <li><a href="#NOT_ALLOWED_ON_NON_LEAF">NOT_ALLOWED_ON_NON_LEAF</a></li>
     * <li><a href="#NOT_ALLOWED_ON_RDN">NOT_ALLOWED_ON_RDN</a></li>
     * <li><a href="#ENTRY_ALREADY_EXISTS">ENTRY_ALREADY_EXISTS</a></li>
     * <li><a href="#OBJECT_CLASS_MODS_PROHIBITED">OBJECT_CLASS_MODS_PROHIBITED</a></li>
     * <li><a href="#AFFECTS_MULTIPLE_DSAS">AFFECTS_MULTIPLE_DSAS</a></li>
     * <li><a href="#OTHER">OTHER</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> EXTENDED_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.SUCCESS );
        set.add( ResultCodeEnum.OPERATIONS_ERROR );
        set.add( ResultCodeEnum.PROTOCOL_ERROR );
        set.add( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.SIZE_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.COMPARE_FALSE );
        set.add( ResultCodeEnum.COMPARE_TRUE );
        set.add( ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.SASL_BIND_IN_PROGRESS );
        set.add( ResultCodeEnum.NO_SUCH_ATTRIBUTE );
        set.add( ResultCodeEnum.UNDEFINED_ATTRIBUTE_TYPE );
        set.add( ResultCodeEnum.INAPPROPRIATE_MATCHING );
        set.add( ResultCodeEnum.CONSTRAINT_VIOLATION );
        set.add( ResultCodeEnum.ATTRIBUTE_OR_VALUE_EXISTS );
        set.add( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX );
        set.add( ResultCodeEnum.NO_SUCH_OBJECT );
        set.add( ResultCodeEnum.ALIAS_PROBLEM );
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.ALIAS_DEREFERENCING_PROBLEM );
        set.add( ResultCodeEnum.INAPPROPRIATE_AUTHENTICATION );
        set.add( ResultCodeEnum.INVALID_CREDENTIALS );
        set.add( ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS );
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.UNAVAILABLE );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.NAMING_VIOLATION );
        set.add( ResultCodeEnum.OBJECT_CLASS_VIOLATION );
        set.add( ResultCodeEnum.NOT_ALLOWED_ON_NON_LEAF );
        set.add( ResultCodeEnum.NOT_ALLOWED_ON_RDN );
        set.add( ResultCodeEnum.ENTRY_ALREADY_EXISTS );
        set.add( ResultCodeEnum.OBJECT_CLASS_MODS_PROHIBITED );
        set.add( ResultCodeEnum.AFFECTS_MULTIPLE_DSAS );
        set.add( ResultCodeEnum.OTHER );
        set.add( ResultCodeEnum.CANCELED );
        EXTENDED_CODES = Collections.unmodifiableSet( set );
    }
    // ------------------------------------------------------------------------
    // Getting Result Code Enumeration Object Using Integer Values
    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // JNDI Exception to ResultCodeEnum Mappings
    // ------------------------------------------------------------------------

    /**
     * A set of ResultCodes containing those that may correspond to NamingException.
     * <ul>
     * <li><a href="#OPERATIONSERROR">operationsError(1)</a></li>
     * <li><a href="#ALIAS_PROBLEM">aliasProblem(33)</a></li>
     * <li><a href="#ALIAS_DEREFERENCING_PROBLEM">aliasDereferencingProblem(36)</a></li>
     * <li><a href="#LOOP_DETECT">loopDetect(54)</a></li>
     * <li><a href="#AFFECTS_MULTIPLE_DSAS">affectsMultipleDSAs(71)</a></li>
     * <li><a href="#OTHER">other(80)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> NAMING_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.OPERATIONS_ERROR );
        set.add( ResultCodeEnum.ALIAS_PROBLEM );
        set.add( ResultCodeEnum.ALIAS_DEREFERENCING_PROBLEM );
        set.add( ResultCodeEnum.LOOP_DETECT );
        set.add( ResultCodeEnum.AFFECTS_MULTIPLE_DSAS );
        set.add( ResultCodeEnum.OTHER );
        NAMING_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a href="#AUTH_METHOD_NOT_SUPPORTED">authMethodNotSupported(7)</a></li>
     * <li><a href="#STRONG_AUTH_REQUIRED">strongAuthRequired(8)</a></li>
     * <li><a href="#CONFIDENTIALITY_REQUIRED">confidentialityRequired(13)</a></li>
     * <li><a
     * href="#INAPPROPRIATE_AUTHENTICATION">inappropriateAuthentication(48)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> AUTHENTICATION_NOT_SUPPORTED_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED );
        set.add( ResultCodeEnum.STRONG_AUTH_REQUIRED );
        set.add( ResultCodeEnum.CONFIDENTIALITY_REQUIRED );
        set.add( ResultCodeEnum.INAPPROPRIATE_AUTHENTICATION );
        AUTHENTICATION_NOT_SUPPORTED_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a href="#BUSY">busy(51)</a></li>
     * <li><a href="#UNAVAILABLE">unavailable(52)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> SERVICE_UNAVAILABLE_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.BUSY );
        set.add( ResultCodeEnum.UNAVAILABLE );
        SERVICE_UNAVAILABLE_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a href="#CONSTRAINT_VIOLATION">constraintViolation(19)</a></li>
     * <li><a href="#INVALID_ATTRIBUTE_SYNTAX">invalidAttributeSyntax(21)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> INVALID_ATTRIBUTE_VALUE_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.CONSTRAINT_VIOLATION );
        set.add( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX );
        INVALID_ATTRIBUTE_VALUE_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    
    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a href="#PARTIAL_RESULTS">partialResults(9)</a></li>
     * <li><a href="#REFERRAL">referral(10)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> PARTIAL_RESULTS_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.PARTIAL_RESULTS );
        set.add( ResultCodeEnum.REFERRAL );
        PARTIAL_RESULTS_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a href="#REFERRAL">referal(9)</a></li>
     * <li><a href="#ADMIN_LIMIT_EXCEEDED">adminLimitExceeded(11)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> LIMIT_EXCEEDED_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.REFERRAL );
        set.add( ResultCodeEnum.ADMIN_LIMIT_EXCEEDED );
        LIMIT_EXCEEDED_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a
     * href="#UNAVAILABLECRITICALEXTENTION">unavailableCriticalExtention(12)</a></li>
     * <li><a href="#UNWILLING_TO_PERFORM">unwillingToPerform(53)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> OPERATION_NOT_SUPPORTED_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
        set.add( ResultCodeEnum.UNWILLING_TO_PERFORM );
        OPERATION_NOT_SUPPORTED_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link Exception}.
     * <ul>
     * <li><a href="#INVALID_DN_SYNTAX">invalidDNSyntax(34)</a></li>
     * <li><a href="#NAMING_VIOLATION">namingViolation(64)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> INVALID_NAME_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.INVALID_DN_SYNTAX );
        set.add( ResultCodeEnum.NAMING_VIOLATION );
        INVALID_NAME_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }

    /**
     * A set of ResultCodes containing those that may correspond to a
     * {@link javax.naming.directory.SchemaViolationException}.
     * <ul>
     * <li><a href="#OBJECT_CLASS_VIOLATION">objectClassViolation(65)</a></li>
     * <li><a href="#NOT_ALLOWED_ON_RDN">notAllowedOnRDN(67)</a></li>
     * <li><a href="#OBJECT_CLASS_MODS_PROHIBITED">objectClassModsProhibited(69)</a></li>
     * </ul>
     */
    private static final Set<ResultCodeEnum> SCHEMA_VIOLATION_EXCEPTION_CODES;

    static
    {
        Set<ResultCodeEnum> set = new HashSet<>();
        set.add( ResultCodeEnum.OBJECT_CLASS_VIOLATION );
        set.add( ResultCodeEnum.NOT_ALLOWED_ON_RDN );
        set.add( ResultCodeEnum.OBJECT_CLASS_MODS_PROHIBITED );
        SCHEMA_VIOLATION_EXCEPTION_CODES = Collections.unmodifiableSet( set );
    }


    /**
     * Private construct so no other instances can be created other than the
     * public static constants in this class.
     * 
     * @param value the integer value of the enumeration.
     * @param message the description of the enumeration.
     */
    ResultCodeEnum( int value, String message )
    {
        this.value = value;
        this.message = message;
    }


    /**
     * @return The integer associated with the result code
     */
    public int getResultCode()
    {
        return value;
    }


    /**
     * Gets the ResultCode enum from its integer value
     * 
     * @param value the ResultCode numneric value
     * @return The integer associated with the result code
     */
    public static ResultCodeEnum getResultCode( int value )
    {
        switch ( value )
        {
            case 0:
                return SUCCESS;
            case 1:
                return OPERATIONS_ERROR;
            case 2:
                return PROTOCOL_ERROR;
            case 3:
                return TIME_LIMIT_EXCEEDED;
            case 4:
                return SIZE_LIMIT_EXCEEDED;
            case 5:
                return COMPARE_FALSE;
            case 6:
                return COMPARE_TRUE;
            case 7:
                return AUTH_METHOD_NOT_SUPPORTED;
            case 8:
                return STRONG_AUTH_REQUIRED;
            case 9:
                return PARTIAL_RESULTS;
            case 10:
                return REFERRAL;
            case 11:
                return ADMIN_LIMIT_EXCEEDED;
            case 12:
                return UNAVAILABLE_CRITICAL_EXTENSION;
            case 13:
                return CONFIDENTIALITY_REQUIRED;
            case 14:
                return SASL_BIND_IN_PROGRESS;
            case 16:
                return NO_SUCH_ATTRIBUTE;
            case 17:
                return UNDEFINED_ATTRIBUTE_TYPE;
            case 18:
                return INAPPROPRIATE_MATCHING;
            case 19:
                return CONSTRAINT_VIOLATION;
            case 20:
                return ATTRIBUTE_OR_VALUE_EXISTS;
            case 21:
                return INVALID_ATTRIBUTE_SYNTAX;
            case 32:
                return NO_SUCH_OBJECT;
            case 33:
                return ALIAS_PROBLEM;
            case 34:
                return INVALID_DN_SYNTAX;
            case 35:
                return UNKNOWN;
            case 36:
                return ALIAS_DEREFERENCING_PROBLEM;
            case 48:
                return INAPPROPRIATE_AUTHENTICATION;
            case 49:
                return INVALID_CREDENTIALS;
            case 50:
                return INSUFFICIENT_ACCESS_RIGHTS;
            case 51:
                return BUSY;
            case 52:
                return UNAVAILABLE;
            case 53:
                return UNWILLING_TO_PERFORM;
            case 54:
                return LOOP_DETECT;
            case 64:
                return NAMING_VIOLATION;
            case 65:
                return OBJECT_CLASS_VIOLATION;
            case 66:
                return NOT_ALLOWED_ON_NON_LEAF;
            case 67:
                return NOT_ALLOWED_ON_RDN;
            case 68:
                return ENTRY_ALREADY_EXISTS;
            case 69:
                return OBJECT_CLASS_MODS_PROHIBITED;
            case 71:
                return AFFECTS_MULTIPLE_DSAS;
            case 80:
                return OTHER;
            case 118:
                return CANCELED;
            case 119:
                return NO_SUCH_OPERATION;
            case 120:
                return TOO_LATE;
            case 121:
                return CANNOT_CANCEL;
            case 4096:
                return E_SYNC_REFRESH_REQUIRED;
            default:
                return UNKNOWN;
        }
    }



    /**
     * @return The value associated with the current element.
     */
    public int getValue()
    {
        return value;
    }


    /**
     * @return The description associated with the current element.
     */
    public String getMessage()
    {
        return message;
    }


    /**
     * Takes a guess at the result code to use if it cannot figure it out from
     * known Throwable to result code mappings. Some however are ambiguous
     * mapping the same Throwable to multiple codes. If no code can be resolved
     * then {@link ResultCodeEnum#OTHER} is returned.
     * 
     * @param t
     *            the throwable to estimate a result code for
     * @param type
     *            the type of operation being performed
     * @return the result code or a good estimate of one
     */
    public static ResultCodeEnum getBestEstimate( Throwable t, MessageTypeEnum type )
    {
        Set<ResultCodeEnum> set = getResultCodes( t );

        if ( set.isEmpty() )
        {
            return ResultCodeEnum.OTHER;
        }

        if ( set.size() == 1 )
        {
            return set.iterator().next();
        }

        if ( type == null )
        {
            Set<ResultCodeEnum> tmp = new HashSet<>();
            tmp.addAll( set );
            tmp.removeAll( NON_ERRONEOUS_CODES );

            if ( tmp.isEmpty() )
            {
                return ResultCodeEnum.OTHER;
            }

            return tmp.iterator().next();
        }

        Set<ResultCodeEnum> candidates;

        switch ( type )
        {
            case ABANDON_REQUEST:
                return set.iterator().next();

            case ADD_REQUEST:
                candidates = intersection( set, ADD_CODES );
                break;

            case ADD_RESPONSE:
                candidates = intersection( set, ADD_CODES );
                break;

            case BIND_REQUEST:
                candidates = intersection( set, BIND_CODES );
                break;

            case BIND_RESPONSE:
                candidates = intersection( set, BIND_CODES );
                break;

            case COMPARE_REQUEST:
                candidates = intersection( set, COMPARE_CODES );
                break;

            case COMPARE_RESPONSE:
                candidates = intersection( set, COMPARE_CODES );
                break;

            case DEL_REQUEST:
                candidates = intersection( set, DELETE_CODES );
                break;

            case DEL_RESPONSE:
                candidates = intersection( set, DELETE_CODES );
                break;

            case EXTENDED_REQUEST:
                candidates = intersection( set, EXTENDED_CODES );
                break;

            case EXTENDED_RESPONSE:
                candidates = intersection( set, EXTENDED_CODES );
                break;

            case MODIFYDN_REQUEST:
                candidates = intersection( set, MODIFYDN_CODES );
                break;

            case MODIFYDN_RESPONSE:
                candidates = intersection( set, MODIFYDN_CODES );
                break;

            case MODIFY_REQUEST:
                candidates = intersection( set, MODIFY_CODES );
                break;

            case MODIFY_RESPONSE:
                candidates = intersection( set, MODIFY_CODES );
                break;

            case SEARCH_REQUEST:
                candidates = intersection( set, SEARCH_CODES );
                break;

            case SEARCH_RESULT_DONE:
                candidates = intersection( set, SEARCH_CODES );
                break;

            case SEARCH_RESULT_ENTRY:
                candidates = intersection( set, SEARCH_CODES );
                break;

            case SEARCH_RESULT_REFERENCE:
                candidates = intersection( set, SEARCH_CODES );
                break;

            case UNBIND_REQUEST:
                return set.iterator().next();

            case INTERMEDIATE_RESPONSE:
                candidates = intersection( set, SEARCH_CODES );
                break;

            default:
                throw new IllegalArgumentException( "Unexpected MessageTypeEnum " + type );
        }

        // we don't want any codes that do not have anything to do w/ errors
        candidates.removeAll( NON_ERRONEOUS_CODES );

        if ( candidates.isEmpty() )
        {
            return ResultCodeEnum.OTHER;
        }

        return candidates.iterator().next();
    }


    private static Set<ResultCodeEnum> intersection( Set<ResultCodeEnum> s1, Set<ResultCodeEnum> s2 )
    {
        if ( s1.isEmpty() || s2.isEmpty() )
        {
            return new HashSet<>();
        }

        Set<ResultCodeEnum> intersection = new HashSet<>();

        if ( s1.size() <= s2.size() )
        {
            for ( ResultCodeEnum item : s1 )
            {
                if ( s2.contains( item ) )
                {
                    intersection.add( item );
                }
            }
        }
        else
        {
            for ( ResultCodeEnum item : s2 )
            {
                if ( s1.contains( item ) )
                {
                    intersection.add( item );
                }
            }
        }

        return intersection;
    }


    /**
     * Gets the set of result codes a Throwable may map to. If the throwable
     * does not map to any result code at all an empty set is returned. The
     * following Throwables and their subclasses map to result codes:
     * 
     * <pre>
     * 
     *  Unambiguous Exceptions
     *  ======================
     * 
     *  CommunicationException              ==&gt; operationsError(1)
     *  TimeLimitExceededException          ==&gt; timeLimitExceeded(3)
     *  SizeLimitExceededException          ==&gt; sizeLimitExceeded(4)
     *  AuthenticationException             ==&gt; invalidCredentials(49)
     *  NoPermissionException               ==&gt; insufficientAccessRights(50)
     *  NoSuchAttributeException            ==&gt; noSuchAttribute(16)
     *  InvalidAttributeIdentifierException ==&gt; undefinedAttributeType(17)
     *  InvalidSearchFilterException        ==&gt; inappropriateMatching(18)
     *  AttributeInUseException             ==&gt; attributeOrValueExists(20)
     *  NameNotFoundException               ==&gt; NO_SUCH_OBJECT(32)
     *  NameAlreadyBoundException           ==&gt; entryAlreadyExists(68)
     *  ContextNotEmptyException            ==&gt; notAllowedOnNonLeaf(66)
     * 
     * 
     *  Ambiguous Exceptions
     *  ====================
     * 
     *  NamingException
     *  ---------------
     *  operationsError(1)
     *  aliasProblem(33)
     *  aliasDereferencingProblem(36)
     *  loopDetect(54)
     *  affectsMultipleDSAs(71)
     *  other(80)
     * 
     *  AuthenticationNotSupportedException
     *  -----------------------------------
     *  authMethodNotSupported (7)
     *  strongAuthRequired (8)
     *  confidentialityRequired (13)
     *  inappropriateAuthentication(48)
     * 
     *  ServiceUnavailableException
     *  ---------------------------
     *  busy(51)
     *  unavailable(52)
     * 
     *  InvalidAttributeValueException
     *  ------------------------------
     *  constraintViolation(19)
     *  invalidAttributeSyntax(21)
     * 
     *  PartialResultException
     *  ----------------------
     *  partialResults(9)
     *  referral(10)
     * 
     *  LimitExceededException
     *  ----------------------
     *  referal(9)
     *  adminLimitExceeded(11)
     * 
     *  OperationNotSupportedException
     *  ------------------------------
     *  unavailableCriticalExtention(12)
     *  unwillingToPerform(53)
     * 
     *  InvalidNameException
     *  --------------------
     *  invalidDNSyntax(34)
     *  namingViolation(64)
     * 
     *  SchemaViolationException
     *  ------------------------
     *  objectClassViolation(65)
     *  notAllowedOnRDN(67)
     *  objectClassModsProhibited(69)
     * 
     * </pre>
     * 
     * @param t
     *            the Throwable to find the result code mappings for
     * @return the set of mapped result codes
     */
    private static Set<ResultCodeEnum> getResultCodes( Throwable t )
    {
        ResultCodeEnum rc = getResultCode( t );
        if ( rc != null )
        {
            return Collections.singleton( rc );
        }

        if ( t instanceof LdapSchemaViolationException )
        {
            return SCHEMA_VIOLATION_EXCEPTION_CODES;
        }

        if ( t instanceof LdapInvalidDnException )
        {
            return INVALID_NAME_EXCEPTION_CODES;
        }

        if ( t instanceof LdapUnwillingToPerformException )
        {
            return OPERATION_NOT_SUPPORTED_EXCEPTION_CODES;
        }

        if ( t instanceof LimitExceededException )
        {
            return LIMIT_EXCEEDED_EXCEPTION_CODES;
        }

        if ( t instanceof PartialResultException )
        {
            return PARTIAL_RESULTS_EXCEPTION_CODES;
        }

        if ( t instanceof LdapInvalidAttributeValueException )
        {
            return INVALID_ATTRIBUTE_VALUE_EXCEPTION_CODES;
        }

        if ( t instanceof LdapServiceUnavailableException )
        {
            return SERVICE_UNAVAILABLE_CODES;
        }

        if ( t instanceof LdapAuthenticationNotSupportedException )
        {
            return AUTHENTICATION_NOT_SUPPORTED_EXCEPTION_CODES;
        }

        // keep this last because others are subtypes and thier evaluation
        // may be shorted otherwise by this comparison here
        if ( t instanceof LdapException )
        {
            return NAMING_EXCEPTION_CODES;
        }

        return EMPTY_RESULT_CODE_SET;
    }


    /**
     * Gets an LDAP result code from a Throwable if it can resolve it
     * unambiguously or returns null if it cannot resolve the exception to a
     * single ResultCode. If the Throwable is an instance of LdapException this
     * is already done for us, otherwise we use the following mapping:
     * 
     * <pre>
     * 
     *  Unambiguous Exceptions
     *  ======================
     * 
     *  CommunicationException              ==&gt; operationsError(1)
     *  TimeLimitExceededException          ==&gt; timeLimitExceeded(3)
     *  SizeLimitExceededException          ==&gt; sizeLimitExceeded(4)
     *  AuthenticationException             ==&gt; invalidCredentials(49)
     *  NoPermissionException               ==&gt; insufficientAccessRights(50)
     *  NoSuchAttributeException            ==&gt; noSuchAttribute(16)
     *  InvalidAttributeIdentifierException ==&gt; undefinedAttributeType(17)
     *  InvalidSearchFilterException        ==&gt; inappropriateMatching(18)
     *  AttributeInUseException             ==&gt; attributeOrValueExists(20)
     *  NameNotFoundException               ==&gt; NO_SUCH_OBJECT(32)
     *  NameAlreadyBoundException           ==&gt; entryAlreadyExists(68)
     *  ContextNotEmptyException            ==&gt; notAllowedOnNonLeaf(66)
     * </pre>
     * 
     * If we cannot find a mapping then null is returned.
     * 
     * @param t The exception for which we need a ResultCodeEnum
     * @return The ResultCodeEnum associated wit the given exception 
     */
    public static ResultCodeEnum getResultCode( Throwable t )
    {
        if ( t instanceof LdapOperationException )
        {
            return ( ( LdapOperationException ) t ).getResultCode();
        }

        if ( t instanceof CommunicationException )
        {
            return ResultCodeEnum.PROTOCOL_ERROR;
        }

        if ( t instanceof LdapTimeLimitExceededException )
        {
            return ResultCodeEnum.TIME_LIMIT_EXCEEDED;
        }

        if ( t instanceof SizeLimitExceededException )
        {
            return ResultCodeEnum.SIZE_LIMIT_EXCEEDED;
        }

        if ( t instanceof LdapAuthenticationException )
        {
            return ResultCodeEnum.INVALID_CREDENTIALS;
        }

        if ( t instanceof LdapNoPermissionException )
        {
            return ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS;
        }

        if ( t instanceof LdapNoSuchAttributeException )
        {
            return ResultCodeEnum.NO_SUCH_ATTRIBUTE;
        }

        if ( t instanceof LdapInvalidAttributeTypeException )
        {
            return ResultCodeEnum.UNDEFINED_ATTRIBUTE_TYPE;
        }

        if ( t instanceof LdapInvalidSearchFilterException )
        {
            return ResultCodeEnum.INAPPROPRIATE_MATCHING;
        }

        if ( t instanceof LdapAttributeInUseException )
        {
            return ResultCodeEnum.ATTRIBUTE_OR_VALUE_EXISTS;
        }

        if ( t instanceof LdapNoSuchObjectException )
        {
            return ResultCodeEnum.NO_SUCH_OBJECT;
        }

        if ( t instanceof LdapEntryAlreadyExistsException )
        {
            return ResultCodeEnum.ENTRY_ALREADY_EXISTS;
        }

        if ( t instanceof LdapContextNotEmptyException )
        {
            return ResultCodeEnum.NOT_ALLOWED_ON_NON_LEAF;
        }

        return null;
    }


    /**
     * Process the response, throwing the associated exception if needed. If the result
     * was SUCCESS, does not return anything but true. 
     * 
     * @param response The response to process
     * @return For the COMPARE_TRUE or COMPARE_FALSE results, return true or false
     * @throws LdapException The associated exception
     */
    public static boolean processResponse( ResultResponse response ) throws LdapException
    {
        LdapResult ldapResult = response.getLdapResult();

        switch ( ldapResult.getResultCode() )
        {
        // Not erroneous code
            case SUCCESS:
            case PARTIAL_RESULTS:
            case REFERRAL:
            case SASL_BIND_IN_PROGRESS:
            case CANCELED:
            case COMPARE_TRUE:
                return true;

            case COMPARE_FALSE:
                return false;

            case INVALID_CREDENTIALS:
                LdapAuthenticationException authenticationException = new LdapAuthenticationException(
                    ldapResult.getDiagnosticMessage() );
                authenticationException.setResolvedDn( ldapResult.getMatchedDn() );

                throw authenticationException;

            case UNWILLING_TO_PERFORM:
            case UNAVAILABLE_CRITICAL_EXTENSION:
                LdapUnwillingToPerformException unwillingToPerformException =
                    new LdapUnwillingToPerformException( ldapResult.getResultCode(), ldapResult.getDiagnosticMessage() );
                unwillingToPerformException.setResolvedDn( ldapResult.getMatchedDn() );

                throw unwillingToPerformException;

            case INSUFFICIENT_ACCESS_RIGHTS:
                LdapNoPermissionException ldapNoPermissionException = new LdapNoPermissionException(
                    ldapResult.getDiagnosticMessage() );
                ldapNoPermissionException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapNoPermissionException;

            case NOT_ALLOWED_ON_NON_LEAF:
                LdapContextNotEmptyException ldapContextNotEmptyException = new LdapContextNotEmptyException(
                    ldapResult.getDiagnosticMessage() );
                ldapContextNotEmptyException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapContextNotEmptyException;

            case NO_SUCH_OBJECT:
                LdapNoSuchObjectException ldapNoSuchObjectException = new LdapNoSuchObjectException(
                    ldapResult.getDiagnosticMessage() );
                ldapNoSuchObjectException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapNoSuchObjectException;

            case NO_SUCH_ATTRIBUTE:
                LdapNoSuchAttributeException ldapNoSuchAttributeException = new LdapNoSuchAttributeException(
                    ldapResult.getDiagnosticMessage() );
                ldapNoSuchAttributeException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapNoSuchAttributeException;

            case ATTRIBUTE_OR_VALUE_EXISTS:
                LdapAttributeInUseException ldapAttributeInUseException = new LdapAttributeInUseException(
                    ldapResult.getDiagnosticMessage() );
                ldapAttributeInUseException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapAttributeInUseException;

            case ENTRY_ALREADY_EXISTS:
                LdapEntryAlreadyExistsException ldapEntryAlreadyExistsException = new LdapEntryAlreadyExistsException(
                    ldapResult.getDiagnosticMessage() );
                ldapEntryAlreadyExistsException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapEntryAlreadyExistsException;

            case OBJECT_CLASS_VIOLATION:
            case NOT_ALLOWED_ON_RDN:
            case OBJECT_CLASS_MODS_PROHIBITED:
                LdapSchemaViolationException ldapSchemaViolationException =
                    new LdapSchemaViolationException( ldapResult.getResultCode(), ldapResult.getDiagnosticMessage() );
                ldapSchemaViolationException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapSchemaViolationException;

            case ALIAS_PROBLEM:
                LdapAliasException ldapAliasException = new LdapAliasException( ldapResult.getDiagnosticMessage() );
                ldapAliasException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapAliasException;

            case AFFECTS_MULTIPLE_DSAS:
                LdapAffectMultipleDsaException ldapAffectMultipleDsaException = new LdapAffectMultipleDsaException(
                    ldapResult.getDiagnosticMessage() );
                ldapAffectMultipleDsaException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapAffectMultipleDsaException;

            case ALIAS_DEREFERENCING_PROBLEM:
                LdapAliasDereferencingException ldapAliasDereferencingException = new LdapAliasDereferencingException(
                    ldapResult.getDiagnosticMessage() );
                ldapAliasDereferencingException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapAliasDereferencingException;

            case AUTH_METHOD_NOT_SUPPORTED:
            case INAPPROPRIATE_AUTHENTICATION:
            case CONFIDENTIALITY_REQUIRED:
                LdapAuthenticationNotSupportedException ldapAuthenticationNotSupportedException =
                    new LdapAuthenticationNotSupportedException( ldapResult.getResultCode(),
                        ldapResult.getDiagnosticMessage() );
                ldapAuthenticationNotSupportedException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapAuthenticationNotSupportedException;

            case BUSY:
            case UNAVAILABLE:
                LdapServiceUnavailableException ldapServiceUnavailableException =
                    new LdapServiceUnavailableException( ldapResult.getResultCode(), ldapResult.getDiagnosticMessage() );
                ldapServiceUnavailableException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapServiceUnavailableException;

            case CONSTRAINT_VIOLATION:
            case INVALID_ATTRIBUTE_SYNTAX:
                LdapInvalidAttributeValueException ldapInvalidAttributeValueException =
                    new LdapInvalidAttributeValueException( ldapResult.getResultCode(),
                        ldapResult.getDiagnosticMessage() );
                ldapInvalidAttributeValueException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapInvalidAttributeValueException;

            case INAPPROPRIATE_MATCHING:
                LdapInvalidSearchFilterException ldapInvalidSearchFilterException = new LdapInvalidSearchFilterException(
                    ldapResult.getDiagnosticMessage() );
                ldapInvalidSearchFilterException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapInvalidSearchFilterException;

            case INVALID_DN_SYNTAX:
            case NAMING_VIOLATION:
                LdapInvalidDnException ldapInvalidDnException =
                    new LdapInvalidDnException( ldapResult.getResultCode(), ldapResult.getDiagnosticMessage() );
                ldapInvalidDnException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapInvalidDnException;

            case LOOP_DETECT:
                LdapLoopDetectedException ldapLoopDetectedException = new LdapLoopDetectedException(
                    ldapResult.getDiagnosticMessage() );
                ldapLoopDetectedException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapLoopDetectedException;

            case OPERATIONS_ERROR:
                LdapOperationErrorException ldapOperationErrorException = new LdapOperationErrorException(
                    ldapResult.getDiagnosticMessage() );
                ldapOperationErrorException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapOperationErrorException;

            case PROTOCOL_ERROR:
                LdapProtocolErrorException ldapProtocolErrorException = new LdapProtocolErrorException(
                    ldapResult.getDiagnosticMessage() );
                ldapProtocolErrorException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapProtocolErrorException;

            case TIME_LIMIT_EXCEEDED:
                LdapTimeLimitExceededException ldapTimeLimitExceededException = new LdapTimeLimitExceededException(
                    ldapResult.getDiagnosticMessage() );
                ldapTimeLimitExceededException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapTimeLimitExceededException;

            case UNDEFINED_ATTRIBUTE_TYPE:
                LdapInvalidAttributeTypeException ldapInvalidAttributeTypeException = new LdapInvalidAttributeTypeException(
                    ldapResult.getDiagnosticMessage() );
                ldapInvalidAttributeTypeException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapInvalidAttributeTypeException;

            case OTHER:
                LdapOtherException ldapOtherException = new LdapOtherException( ldapResult.getDiagnosticMessage() );
                ldapOtherException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapOtherException;

            case SIZE_LIMIT_EXCEEDED:
                LdapSizeLimitExceededException ldapSizeLimitExceededException = new LdapSizeLimitExceededException(
                    ldapResult.getDiagnosticMessage() );
                ldapSizeLimitExceededException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapSizeLimitExceededException;

            case STRONG_AUTH_REQUIRED:
                LdapStrongAuthenticationRequiredException ldapStrongAuthenticationRequiredException =
                    new LdapStrongAuthenticationRequiredException( ldapResult.getDiagnosticMessage() );
                ldapStrongAuthenticationRequiredException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapStrongAuthenticationRequiredException;

            case ADMIN_LIMIT_EXCEEDED:
                LdapAdminLimitExceededException ldapAdminLimitExceededException =
                    new LdapAdminLimitExceededException( ldapResult.getDiagnosticMessage() );
                ldapAdminLimitExceededException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapAdminLimitExceededException;

            case TOO_LATE:
                LdapTooLateException ldapTooLateException = new LdapTooLateException( ldapResult.getDiagnosticMessage() );
                ldapTooLateException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapTooLateException;

            case UNKNOWN:
                LdapUnknownException ldapUnknownException = new LdapUnknownException( ldapResult.getDiagnosticMessage() );
                ldapUnknownException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapUnknownException;

            case CANNOT_CANCEL:
                LdapCannotCancelException ldapCannotCancelException = new LdapCannotCancelException(
                    ldapResult.getDiagnosticMessage() );
                ldapCannotCancelException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapCannotCancelException;

            case NO_SUCH_OPERATION:
                LdapNoSuchOperationException ldapNoSuchOperationException = new LdapNoSuchOperationException(
                    ldapResult.getDiagnosticMessage() );
                ldapNoSuchOperationException.setResolvedDn( ldapResult.getMatchedDn() );

                throw ldapNoSuchOperationException;

            case E_SYNC_REFRESH_REQUIRED:
                // This is a specific error message. We won't encapsulate it in a dedicated exception
                // Fallthrough

            default:
                LdapOperationException exception = new LdapOperationException( ldapResult.getResultCode(),
                    ldapResult.getDiagnosticMessage() );
                exception.setResolvedDn( ldapResult.getMatchedDn() );

                throw exception;
        }
    }
}
