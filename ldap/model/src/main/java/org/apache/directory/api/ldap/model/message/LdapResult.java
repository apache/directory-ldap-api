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


import org.apache.directory.api.ldap.model.name.Dn;


/**
 * LDAPv3 result structure embedded into Responses. See section 4.1.9 in <a
 * href="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</a> for a description of 
 * the LDAPResult ASN.1 structure, here's a snippet from it:
 * 
 * <pre>
 *   The LDAPResult is the construct used in this protocol to return
 *   success or failure indications from servers to clients. To various
 *  requests, servers will return responses containing the elements found
 *  in LDAPResult to indicate the final status of the protocol operation
 *  request.

 * LDAPResult ::= SEQUENCE {
 *     resultCode         ENUMERATED {
 *         success                      (0),
 *         operationsError              (1),
 *         protocolError                (2),
 *         timeLimitExceeded            (3),
 *         sizeLimitExceeded            (4),
 *         compareFalse                 (5),
 *         compareTrue                  (6),
 *         authMethodNotSupported       (7),
 *         strongerAuthRequired         (8),
 *              -- 9 reserved --
 *         referral                     (10),
 *         adminLimitExceeded           (11),
 *         unavailableCriticalExtension (12),
 *         confidentialityRequired      (13),
 *         saslBindInProgress           (14),
 *         noSuchAttribute              (16),
 *         undefinedAttributeType       (17),
 *         inappropriateMatching        (18),
 *         constraintViolation          (19),
 *         attributeOrValueExists       (20),
 *         invalidAttributeSyntax       (21),
 *              -- 22-31 unused --
 *         noSuchObject                 (32),
 *         aliasProblem                 (33),
 *         invalidDNSyntax              (34),
 *              -- 35 reserved for undefined isLeaf --
 *         aliasDereferencingProblem    (36),
 *              -- 37-47 unused --
 *         inappropriateAuthentication  (48),
 *         invalidCredentials           (49),
 *         insufficientAccessRights     (50),
 *         busy                         (51),
 *         unavailable                  (52),
 *         unwillingToPerform           (53),
 *         loopDetect                   (54),
 *              -- 55-63 unused --
 *         namingViolation              (64),
 *         objectClassViolation         (65),
 *         notAllowedOnNonLeaf          (66),
 *         notAllowedOnRDN              (67),
 *         entryAlreadyExists           (68),
 *         objectClassModsProhibited    (69),
 *              -- 70 reserved for CLDAP --
 *         affectsMultipleDSAs          (71),
 *              -- 72-79 unused --
 *         other                        (80),
 *         ...  },
 *     matchedDN          LDAPDN,
 *     diagnosticMessage  LDAPString,
 *     referral           [3] Referral OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapResult
{
    /**
     * Gets the result code enumeration associated with the response.
     * Corresponds to the <b> resultCode </b> field within the LDAPResult ASN.1
     * structure.
     * 
     * @return the result code enum value.
     */
    ResultCodeEnum getResultCode();


    /**
     * Sets the result code enumeration associated with the response.
     * Corresponds to the <b> resultCode </b> field within the LDAPResult ASN.1
     * structure.
     * 
     * @param resultCode the result code enum value.
     */
    void setResultCode( ResultCodeEnum resultCode );


    /**
     * Gets the lowest entry in the directory that was matched. For result codes
     * of noSuchObject, aliasProblem, invalidDNSyntax and
     * aliasDereferencingProblem, the matchedDN field is set to the name of the
     * lowest entry (object or alias) in the directory that was matched. If no
     * aliases were dereferenced while attempting to locate the entry, this will
     * be a truncated form of the name provided, or if aliases were
     * dereferenced, of the resulting name, as defined in section 12.5 of X.511
     * [8]. The matchedDN field is to be set to a zero length string with all
     * other result codes.
     * 
     * @return the Dn of the lowest matched entry.
     */
    Dn getMatchedDn();


    /**
     * Sets the lowest entry in the directory that was matched.
     * 
     * @see #getMatchedDn()
     * @param dn the Dn of the lowest matched entry.
     */
    void setMatchedDn( Dn dn );


    /**
     * Gets the descriptive diagnostic message associated with the error code. May be
     * null for SUCCESS, COMPARETRUE, COMPAREFALSE and REFERRAL operations.
     * 
     * @return the descriptive diagnostic message.
     */
    String getDiagnosticMessage();


    /**
     * Sets the descriptive diagnostic message associated with the error code. May be
     * null for SUCCESS, COMPARETRUE, and COMPAREFALSE operations.
     * 
     * @param diagnosticMessage the descriptive diagnostic message.
     */
    void setDiagnosticMessage( String diagnosticMessage );


    /**
     * Gets whether or not this result represents a Referral. For referrals the
     * error code is set to REFERRAL and the referral property is not null.
     * 
     * @return true if this result represents a referral.
     */
    boolean isReferral();


    /**
     * Gets the Referral associated with this LdapResult if the resultCode
     * property is set to the REFERRAL ResultCodeEnum.
     * 
     * @return the referral on REFERRAL resultCode, null on all others.
     */
    Referral getReferral();


    /**
     * Sets the Referral associated with this LdapResult if the resultCode
     * property is set to the REFERRAL ResultCodeEnum. Setting this property
     * will result in a true return from isReferral and the resultCode should be
     * set to REFERRAL.
     * 
     * @param referral optional referral on REFERRAL errors.
     */
    void setReferral( Referral referral );


    /**
     * Tells if the LdapResult is a success, with no added information. The
     * MatchedDn will be empty, as the diagnostic message and the referral.
     * The ResultCode will always be 0.
     * 
     * @return True if the LdapResult is SUCCESS.
     */
    boolean isDefaultSuccess();
}
