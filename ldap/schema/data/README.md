#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

# Schemma Data

## OID Allocation Policy (generated using /src/main/scripts/oid_allocation.pl)

OID values are allocated as follows:

### `ou=syntaxes` and `ou=syntaxCheckers`

- 1.3.6.1.4.1.18060.0.4.1.0.0: Java Byte
- 1.3.6.1.4.1.18060.0.4.1.0.2: Java Short
- 1.3.6.1.4.1.18060.0.4.1.0.3: Java Long
- 1.3.6.1.4.1.18060.0.4.1.0.4: Java Int
- 1.3.6.1.4.1.18060.0.4.1.0.10: Search Scope
- 1.3.6.1.4.1.18060.0.4.1.0.11: Deref Alias

### `ou=comparators` and `ou=matchingRules` and `ou=normalizers`

- 1.3.6.1.4.1.18060.0.4.1.1.1: exactDnAsStringMatch
- 1.3.6.1.4.1.18060.0.4.1.1.2: bigIntegerMatch
- 1.3.6.1.4.1.18060.0.4.1.1.3: jdbmStringMatch

### `ou=attributeTypes`


#### Base Bean

- 1.3.6.1.4.1.18060.0.4.1.2.3: apachePresence
- 1.3.6.1.4.1.18060.0.4.1.2.4: apacheOneLevel
- 1.3.6.1.4.1.18060.0.4.1.2.5: apacheOneAlias
- 1.3.6.1.4.1.18060.0.4.1.2.6: apacheSubAlias
- 1.3.6.1.4.1.18060.0.4.1.2.7: apacheAlias
- 1.3.6.1.4.1.18060.0.4.1.2.8: prefNodeName
- 1.3.6.1.4.1.18060.0.4.1.2.9: apacheSamType
- 1.3.6.1.4.1.18060.0.4.1.2.10: autonomousAreaSubentry
- 1.3.6.1.4.1.18060.0.4.1.2.11: accessControlSubentries
- 1.3.6.1.4.1.18060.0.4.1.2.15: apacheServicePid
- 1.3.6.1.4.1.18060.0.4.1.2.16: apacheServiceFactoryPid
- 1.3.6.1.4.1.18060.0.4.1.2.17: apacheCatalogEntryName
- 1.3.6.1.4.1.18060.0.4.1.2.18: apacheCatalogEntryBaseDn
- 1.3.6.1.4.1.18060.0.4.1.2.19: windowsFilePath
- 1.3.6.1.4.1.18060.0.4.1.2.20: unixFilePath
- 1.3.6.1.4.1.18060.0.4.1.2.21: fullyQualifiedJavaClassName
- 1.3.6.1.4.1.18060.0.4.1.2.22: javaClassByteCode
- 1.3.6.1.4.1.18060.0.4.1.2.23: classLoaderDefaultSearchContext
- 1.3.6.1.4.1.18060.0.4.1.2.25: prescriptiveTriggerSpecification
- 1.3.6.1.4.1.18060.0.4.1.2.26: entryTriggerSpecification
- 1.3.6.1.4.1.18060.0.4.1.2.27: triggerExecutionSubentries
- 1.3.6.1.4.1.18060.0.4.1.2.28: triggerExecutionSubentry
- 1.3.6.1.4.1.18060.0.4.1.2.31: entryDeleted
- 1.3.6.1.4.1.18060.0.4.1.2.32: comparators
- 1.3.6.1.4.1.18060.0.4.1.2.33: normalizers
- 1.3.6.1.4.1.18060.0.4.1.2.34: syntaxCheckers
- 1.3.6.1.4.1.18060.0.4.1.2.35: schemaModifyTimestamp
- 1.3.6.1.4.1.18060.0.4.1.2.36: schemaModifiersName
- 1.3.6.1.4.1.18060.0.4.1.2.37: subschemaSubentryName
- 1.3.6.1.4.1.18060.0.4.1.2.38: privateKeyFormat
- 1.3.6.1.4.1.18060.0.4.1.2.39: keyAlgorithm
- 1.3.6.1.4.1.18060.0.4.1.2.40: privateKey
- 1.3.6.1.4.1.18060.0.4.1.2.41: publicKeyFormat
- 1.3.6.1.4.1.18060.0.4.1.2.42: publicKey
- 1.3.6.1.4.1.18060.0.4.1.2.43: apacheSubLevel
- 1.3.6.1.4.1.18060.0.4.1.2.44: revisions
- 1.3.6.1.4.1.18060.0.4.1.2.45: changeTime
- 1.3.6.1.4.1.18060.0.4.1.2.46: changeType
- 1.3.6.1.4.1.18060.0.4.1.2.47: rev
- 1.3.6.1.4.1.18060.0.4.1.2.48: committer
- 1.3.6.1.4.1.18060.0.4.1.2.49: changeLogContext
- 1.3.6.1.4.1.18060.0.4.1.2.50: apacheRdn
- 1.3.6.1.4.1.18060.0.4.1.2.51: entryParentId
- 1.3.6.1.4.1.18060.0.4.1.2.61: ads-transportAddress
- 1.3.6.1.4.1.18060.0.4.1.2.62: ads-transportBacklog
- 1.3.6.1.4.1.18060.0.4.1.2.63: ads-transportEnableSSL
- 1.3.6.1.4.1.18060.0.4.1.2.64: ads-transportNbThreads
- 1.3.6.1.4.1.18060.0.4.1.2.65: ads-needClientAuth
- 1.3.6.1.4.1.18060.0.4.1.2.66: ads-wantClientAuth
- 1.3.6.1.4.1.18060.0.4.1.2.67: ads-enabledProtocols
- 1.3.6.1.4.1.18060.0.4.1.2.68: ads-enabledCiphers

#### Directory Service

- 1.3.6.1.4.1.18060.0.4.1.2.100: ads-directoryServiceId
- 1.3.6.1.4.1.18060.0.4.1.2.101: ads-dsAccessControlEnabled
- 1.3.6.1.4.1.18060.0.4.1.2.102: ads-dsAllowAnonymousAccess
- 1.3.6.1.4.1.18060.0.4.1.2.103: ads-dsDenormalizeOpAttrsEnabled
- 1.3.6.1.4.1.18060.0.4.1.2.104: ads-dsPasswordHidden
- 1.3.6.1.4.1.18060.0.4.1.2.110: ads-maxPDUSize
- 1.3.6.1.4.1.18060.0.4.1.2.111: ads-dsSyncPeriodMillis
- 1.3.6.1.4.1.18060.0.4.1.2.112: ads-dsReplicaId
- 1.3.6.1.4.1.18060.0.4.1.2.113: ads-dsTestEntries
- 1.3.6.1.4.1.18060.0.4.1.2.120: ads-changeLogId
- 1.3.6.1.4.1.18060.0.4.1.2.121: ads-changeLogExposed
- 1.3.6.1.4.1.18060.0.4.1.2.130: ads-interceptorId
- 1.3.6.1.4.1.18060.0.4.1.2.131: ads-interceptorOrder
- 1.3.6.1.4.1.18060.0.4.1.2.141: ads-journalRotation
- 1.3.6.1.4.1.18060.0.4.1.2.142: ads-journalWorkingDir
- 1.3.6.1.4.1.18060.0.4.1.2.143: ads-journalFileName
- 1.3.6.1.4.1.18060.0.4.1.2.144: ads-journalId
- 1.3.6.1.4.1.18060.0.4.1.2.150: ads-partitionId
- 1.3.6.1.4.1.18060.0.4.1.2.151: ads-partitionSuffix
- 1.3.6.1.4.1.18060.0.4.1.2.153: ads-partitionCacheSize
- 1.3.6.1.4.1.18060.0.4.1.2.154: ads-contextEntry
- 1.3.6.1.4.1.18060.0.4.1.2.160: ads-indexAttributeId
- 1.3.6.1.4.1.18060.0.4.1.2.161: ads-indexFileName
- 1.3.6.1.4.1.18060.0.4.1.2.162: ads-indexWorkingDir
- 1.3.6.1.4.1.18060.0.4.1.2.163: ads-indexNumDupLimit
- 1.3.6.1.4.1.18060.0.4.1.2.164: ads-indexCacheSize
- 1.3.6.1.4.1.18060.0.4.1.2.165: ads-indexHasReverse
- 1.3.6.1.4.1.18060.0.4.1.2.200: ads-transportId
- 1.3.6.1.4.1.18060.0.4.1.2.250: ads-serverId
- 1.3.6.1.4.1.18060.0.4.1.2.252: ads-Id
- 1.3.6.1.4.1.18060.0.4.1.2.253: ads-extendedOpId

#### LDAP Server

- 1.3.6.1.4.1.18060.0.4.1.2.300: ads-confidentialityRequired
- 1.3.6.1.4.1.18060.0.4.1.2.301: ads-allowAnonymousAccess
- 1.3.6.1.4.1.18060.0.4.1.2.302: ads-maxSizeLimit
- 1.3.6.1.4.1.18060.0.4.1.2.303: ads-maxTimeLimit
- 1.3.6.1.4.1.18060.0.4.1.2.304: ads-saslHost
- 1.3.6.1.4.1.18060.0.4.1.2.305: ads-saslPrincipal
- 1.3.6.1.4.1.18060.0.4.1.2.306: ads-saslRealms
- 1.3.6.1.4.1.18060.0.4.1.2.308: ads-keystoreFile
- 1.3.6.1.4.1.18060.0.4.1.2.309: ads-certificatePassword
- 1.3.6.1.4.1.18060.0.4.1.2.310: ads-replConsumerImpl

#### Kerberos Server

- 1.3.6.1.4.1.18060.0.4.1.2.400: ads-krbAllowableClockSkew
- 1.3.6.1.4.1.18060.0.4.1.2.401: ads-krbEncryptionTypes
- 1.3.6.1.4.1.18060.0.4.1.2.402: ads-krbEmptyAddressesAllowed
- 1.3.6.1.4.1.18060.0.4.1.2.403: ads-krbForwardableAllowed
- 1.3.6.1.4.1.18060.0.4.1.2.404: ads-krbPaEncTimestampRequired
- 1.3.6.1.4.1.18060.0.4.1.2.405: ads-krbPostdatedAllowed
- 1.3.6.1.4.1.18060.0.4.1.2.406: ads-krbProxiableAllowed
- 1.3.6.1.4.1.18060.0.4.1.2.407: ads-krbRenewableAllowed
- 1.3.6.1.4.1.18060.0.4.1.2.408: ads-krbKdcPrincipal
- 1.3.6.1.4.1.18060.0.4.1.2.409: ads-krbMaximumRenewableLifetime
- 1.3.6.1.4.1.18060.0.4.1.2.410: ads-krbMaximumTicketLifetime
- 1.3.6.1.4.1.18060.0.4.1.2.411: ads-krbPrimaryRealm
- 1.3.6.1.4.1.18060.0.4.1.2.412: ads-krbBodyChecksumVerified

#### ChangePassword Server

- 1.3.6.1.4.1.18060.0.4.1.2.800: ads-chgPwdPolicyCategoryCount
- 1.3.6.1.4.1.18060.0.4.1.2.801: ads-chgPwdPolicyPasswordLength
- 1.3.6.1.4.1.18060.0.4.1.2.802: ads-chgPwdPolicyTokenSize
- 1.3.6.1.4.1.18060.0.4.1.2.803: ads-chgPwdServicePrincipal
- 1.3.6.1.4.1.18060.0.4.1.2.804: ads-interceptorClassName
- 1.3.6.1.4.1.18060.0.4.1.2.805: ads-enabled
- 1.3.6.1.4.1.18060.0.4.1.2.806: ads-partitionSyncOnWrite
- 1.3.6.1.4.1.18060.0.4.1.2.807: ads-jdbmPartitionOptimizerEnabled
- 1.3.6.1.4.1.18060.0.4.1.2.808: ads-saslMechName
- 1.3.6.1.4.1.18060.0.4.1.2.809: ads-ntlmMechProvider
- 1.3.6.1.4.1.18060.0.4.1.2.810: ads-saslMechClassName
- 1.3.6.1.4.1.18060.0.4.1.2.811: ads-extendedOpHandlerClass
- 1.3.6.1.4.1.18060.0.4.1.2.812: ads-systemPort
- 1.3.6.1.4.1.18060.0.4.1.2.813: ads-httpWarFile
- 1.3.6.1.4.1.18060.0.4.1.2.814: ads-httpAppCtxPath
- 1.3.6.1.4.1.18060.0.4.1.2.816: ads-httpConfFile
- 1.3.6.1.4.1.18060.0.4.1.2.817: ads-replSearchFilter
- 1.3.6.1.4.1.18060.0.4.1.2.818: ads-replLastSentCsn
- 1.3.6.1.4.1.18060.0.4.1.2.819: ads-replAliasDerefMode
- 1.3.6.1.4.1.18060.0.4.1.2.820: ads-searchBaseDN
- 1.3.6.1.4.1.18060.0.4.1.2.821: ads-replSearchScope
- 1.3.6.1.4.1.18060.0.4.1.2.822: ads-replRefreshNPersist
- 1.3.6.1.4.1.18060.0.4.1.2.823: ads-replProvHostName
- 1.3.6.1.4.1.18060.0.4.1.2.824: ads-replProvPort
- 1.3.6.1.4.1.18060.0.4.1.2.825: ads-replUserDn
- 1.3.6.1.4.1.18060.0.4.1.2.826: ads-replUserPassword
- 1.3.6.1.4.1.18060.0.4.1.2.827: ads-replRefreshInterval
- 1.3.6.1.4.1.18060.0.4.1.2.828: ads-replAttributes
- 1.3.6.1.4.1.18060.0.4.1.2.829: ads-replSearchSizeLimit
- 1.3.6.1.4.1.18060.0.4.1.2.830: ads-replSearchTimeOut
- 1.3.6.1.4.1.18060.0.4.1.2.831: ads-replCookie
- 1.3.6.1.4.1.18060.0.4.1.2.832: ads-replReqHandler
- 1.3.6.1.4.1.18060.0.4.1.2.833: ads-replUseTls
- 1.3.6.1.4.1.18060.0.4.1.2.834: ads-replStrictCertValidation
- 1.3.6.1.4.1.18060.0.4.1.2.837: ads-replConsumerId
- 1.3.6.1.4.1.18060.0.4.1.2.838: ads-replEnabled

#### Password Policy

- 1.3.6.1.4.1.18060.0.4.1.2.900: ads-pwdAttribute
- 1.3.6.1.4.1.18060.0.4.1.2.901: ads-pwdMinAge
- 1.3.6.1.4.1.18060.0.4.1.2.902: ads-pwdMaxAge
- 1.3.6.1.4.1.18060.0.4.1.2.903: ads-pwdInHistory
- 1.3.6.1.4.1.18060.0.4.1.2.904: ads-pwdCheckQuality
- 1.3.6.1.4.1.18060.0.4.1.2.905: ads-pwdMinLength
- 1.3.6.1.4.1.18060.0.4.1.2.906: ads-pwdMaxLength
- 1.3.6.1.4.1.18060.0.4.1.2.907: ads-pwdExpireWarning
- 1.3.6.1.4.1.18060.0.4.1.2.908: ads-pwdGraceAuthNLimit
- 1.3.6.1.4.1.18060.0.4.1.2.909: ads-pwdGraceExpire
- 1.3.6.1.4.1.18060.0.4.1.2.910: ads-pwdLockout
- 1.3.6.1.4.1.18060.0.4.1.2.911: ads-pwdLockoutDuration
- 1.3.6.1.4.1.18060.0.4.1.2.912: ads-pwdMaxFailure
- 1.3.6.1.4.1.18060.0.4.1.2.913: ads-pwdFailureCountInterval
- 1.3.6.1.4.1.18060.0.4.1.2.914: ads-pwdMustChange
- 1.3.6.1.4.1.18060.0.4.1.2.915: ads-pwdAllowUserChange
- 1.3.6.1.4.1.18060.0.4.1.2.916: ads-pwdSafeModify
- 1.3.6.1.4.1.18060.0.4.1.2.917: ads-pwdMinDelay
- 1.3.6.1.4.1.18060.0.4.1.2.918: ads-pwdMaxDelay
- 1.3.6.1.4.1.18060.0.4.1.2.919: ads-pwdMaxIdle
- 1.3.6.1.4.1.18060.0.4.1.2.920: ads-replLogMaxIdle
- 1.3.6.1.4.1.18060.0.4.1.2.921: ads-pwdId
- 1.3.6.1.4.1.18060.0.4.1.2.922: ads-replLogPurgeThresholdCount
- 1.3.6.1.4.1.18060.0.4.1.2.923: ads-replPingerSleep
- 1.3.6.1.4.1.18060.0.4.1.2.925: ads-pwdValidator
- 1.3.6.1.4.1.18060.0.4.1.2.930: ads-authenticatorId
- 1.3.6.1.4.1.18060.0.4.1.2.931: ads-delegateHost
- 1.3.6.1.4.1.18060.0.4.1.2.932: ads-delegatePort
- 1.3.6.1.4.1.18060.0.4.1.2.933: ads-delegateSsl
- 1.3.6.1.4.1.18060.0.4.1.2.934: ads-authenticatorClass
- 1.3.6.1.4.1.18060.0.4.1.2.935: ads-baseDn
- 1.3.6.1.4.1.18060.0.4.1.2.936: ads-delegateTls
- 1.3.6.1.4.1.18060.0.4.1.2.937: ads-delegateSslTrustManager
- 1.3.6.1.4.1.18060.0.4.1.2.938: ads-delegateTlsTrustManager

### `ou=objectClasses`


#### Base Bean

- 1.3.6.1.4.1.18060.0.4.1.3.0: ads-base
- 1.3.6.1.4.1.18060.0.4.1.3.1: prefNode
- 1.3.6.1.4.1.18060.0.4.1.3.3: apacheServiceConfiguration
- 1.3.6.1.4.1.18060.0.4.1.3.4: apacheFactoryConfiguration
- 1.3.6.1.4.1.18060.0.4.1.3.5: apacheCatalogEntry
- 1.3.6.1.4.1.18060.0.4.1.3.6: windowsFile
- 1.3.6.1.4.1.18060.0.4.1.3.7: unixFile
- 1.3.6.1.4.1.18060.0.4.1.3.8: javaClass
- 1.3.6.1.4.1.18060.0.4.1.3.9: apacheSubschema
- 1.3.6.1.4.1.18060.0.4.1.3.10: schemaModificationAttributes
- 1.3.6.1.4.1.18060.0.4.1.3.11: tlsKeyInfo
- 1.3.6.1.4.1.18060.0.4.1.3.12: changeLogEvent
- 1.3.6.1.4.1.18060.0.4.1.3.13: tag
- 1.3.6.1.4.1.18060.0.4.1.3.18: ads-transport
- 1.3.6.1.4.1.18060.0.4.1.3.19: ads-tcpTransport
- 1.3.6.1.4.1.18060.0.4.1.3.20: ads-udpTransport

#### Directory Service

- 1.3.6.1.4.1.18060.0.4.1.3.100: ads-directoryService
- 1.3.6.1.4.1.18060.0.4.1.3.120: ads-changeLog
- 1.3.6.1.4.1.18060.0.4.1.3.130: ads-interceptor
- 1.3.6.1.4.1.18060.0.4.1.3.131: ads-authenticationInterceptor
- 1.3.6.1.4.1.18060.0.4.1.3.140: ads-journal
- 1.3.6.1.4.1.18060.0.4.1.3.150: ads-partition
- 1.3.6.1.4.1.18060.0.4.1.3.151: ads-jdbmPartition
- 1.3.6.1.4.1.18060.0.4.1.3.160: ads-index
- 1.3.6.1.4.1.18060.0.4.1.3.161: ads-jdbmIndex
- 1.3.6.1.4.1.18060.0.4.1.3.250: ads-server
- 1.3.6.1.4.1.18060.0.4.1.3.260: ads-dsBasedServer

#### LDAP Server

- 1.3.6.1.4.1.18060.0.4.1.3.300: ads-ldapServer

#### Kerberos Server

- 1.3.6.1.4.1.18060.0.4.1.3.400: ads-kdcServer

#### DNS Server

- 1.3.6.1.4.1.18060.0.4.1.3.500: ads-dnsServer

#### DHCP Server

- 1.3.6.1.4.1.18060.0.4.1.3.600: ads-dhcpServer

#### NTP Server

- 1.3.6.1.4.1.18060.0.4.1.3.700: ads-ntpServer

#### ChangePassword Server

- 1.3.6.1.4.1.18060.0.4.1.3.800: ads-changePasswordServer
- 1.3.6.1.4.1.18060.0.4.1.3.801: ads-saslMechHandler
- 1.3.6.1.4.1.18060.0.4.1.3.802: ads-extendedOpHandler
- 1.3.6.1.4.1.18060.0.4.1.3.803: ads-httpWebApp
- 1.3.6.1.4.1.18060.0.4.1.3.804: ads-httpServer
- 1.3.6.1.4.1.18060.0.4.1.3.805: ads-replEventLog
- 1.3.6.1.4.1.18060.0.4.1.3.806: ads-replConsumer

#### Password Policy

- 1.3.6.1.4.1.18060.0.4.1.3.900: ads-passwordPolicy
- 1.3.6.1.4.1.18060.0.4.1.3.901: ads-authenticator
- 1.3.6.1.4.1.18060.0.4.1.3.902: ads-authenticatorImpl
- 1.3.6.1.4.1.18060.0.4.1.3.904: ads-delegatingAuthenticator
- 1.3.6.1.4.1.18060.0.4.1.3.905: ads-mavibotIndex
- 1.3.6.1.4.1.18060.0.4.1.3.906: ads-mavibotPartition
- 1.3.6.1.4.1.18060.0.4.1.5.1: storedProcLangId
- 1.3.6.1.4.1.18060.0.4.1.5.2: storedProcUnitName
- 1.3.6.1.4.1.18060.0.4.1.5.3: storedProcUnit
- 1.3.6.1.4.1.18060.0.4.1.5.4: javaByteCode
- 1.3.6.1.4.1.18060.0.4.1.5.5: javaStoredProcUnit
- 1.3.6.1.4.1.18060.0.4.1.5.6: javaxScriptLangId
- 1.3.6.1.4.1.18060.0.4.1.5.7: javaxScriptCode
- 1.3.6.1.4.1.18060.0.4.1.5.8: javaxScriptStoredProcUnit

