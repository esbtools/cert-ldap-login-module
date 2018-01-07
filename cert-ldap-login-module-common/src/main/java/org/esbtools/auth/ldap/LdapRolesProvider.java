/*
 Copyright 2017 esbtools Contributors and/or its affiliates.

 This file is part of esbtools.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.esbtools.auth.ldap;

import org.esbtools.auth.util.RolesProvider;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.DebugType;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocketFactory;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * Fetches user roles from ldap. Pools ldap connections. See {@link LdapConfiguration} for
 * confiugration options.
 *
 * Ldap connection pool is created per @{link {@link LdapRolesProvider} instance. Most likely
 * you'll want to use this class as a singleton.
 *
 *
 * @author mpatercz
 *
 */
public class LdapRolesProvider implements RolesProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(LdapRolesProvider.class);

    private final String searchBase;

    private final LdapConfiguration ldapConfiguration;

    private final LDAPConnection ldapConnection;

    // Connection pool needs to be a singleton
    /**
     * @{code null} until {@link #connectIfNeeded()} is called and successful.
     */
    private LDAPConnectionPool connectionPool;
    private volatile LDAPException connectionException;
    private volatile Instant lastConnectionAttempt;
    private final AtomicBoolean attemptingConnect = new AtomicBoolean(false);

    public LdapRolesProvider(String searchBase, LdapConfiguration ldapConfiguration) throws Exception {
        this(searchBase, ldapConfiguration, true);
    }

    public LdapRolesProvider(String searchBase, LdapConfiguration ldapConfiguration,
            boolean failFast) throws Exception {
        LOGGER.debug("Creating esbtoolsLdapRoleProvider");

        Objects.requireNonNull(searchBase);
        Objects.requireNonNull(ldapConfiguration);

        this.searchBase = searchBase;
        this.ldapConfiguration = ldapConfiguration;
        this.ldapConnection = getLdapConnection(ldapConfiguration);

        try {
            connectIfNeeded();
        } catch (LDAPException e) {
            if (failFast) {
                throw e;
            } else {
                LOGGER.warn("Failed to connect to LDAP server, will retry on next lookup after " +
                    "{} seconds.", ldapConfiguration.getRetryIntervalSeconds(), e);
            }
        }
    }

    private static LDAPConnection getLdapConnection(LdapConfiguration ldapConfiguration) throws GeneralSecurityException {
        if (ldapConfiguration.isDebug()) {
            // bridge java.util.Logger output to log4j
            System.setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");

            // setting the ldap debug level...
            System.setProperty("com.unboundid.ldap.sdk.debug.enabled", "true");
            System.setProperty("com.unboundid.ldap.sdk.debug.level", "FINEST");
            System.setProperty("com.unboundid.ldap.sdk.debug.type", DebugType.getTypeNameList());
        }

        LDAPConnection ldapConnection;

        LDAPConnectionOptions options = new LDAPConnectionOptions();

        // A value which specifies the maximum length of time in milliseconds that an attempt to establish a connection should be allowed to block before failing. By default, a timeout of 60,000 milliseconds (1 minute) will be used.
        options.setConnectTimeoutMillis(ldapConfiguration.getConnectionTimeoutMS());
        // A value which specifies the default timeout in milliseconds that the SDK should wait for a response from the server before failing. By default, a timeout of 300,000 milliseconds (5 minutes) will be used.
        options.setResponseTimeoutMillis(ldapConfiguration.getResponseTimeoutMS());
        // A flag that indicates whether to use the SO_KEEPALIVE socket option to attempt to more quickly detect when idle TCP connections have been lost or to prevent them from being unexpectedly closed by intermediate network hardware. By default, the SO_KEEPALIVE socket option will be used.
        options.setUseKeepAlive(ldapConfiguration.isKeepAlive());

        if (ldapConfiguration.getUseSSL()) {
            TrustStoreTrustManager trustStoreTrustManager = new TrustStoreTrustManager(
                ldapConfiguration.getTrustStore(),
                ldapConfiguration.getTrustStorePassword().toCharArray(),
                "JKS",
                true);
            SSLSocketFactory socketFactory = new SSLUtil(trustStoreTrustManager).createSSLSocketFactory();

            ldapConnection = new LDAPConnection(socketFactory, options);
        } else {
            LOGGER.warn("Not using SSL to connect to ldap. This is very insecure - do not use in prod environments!");

            ldapConnection = new LDAPConnection(options);
        }

        return ldapConnection;
    }

    private void connectIfNeeded() throws LDAPException {
        if (connectionPool != null) {
            return;
        }

        if (!readyForConnectionAttempt()) {
            // It's too early to retry connecting again.
            throw lastSeenConnectionException();
        }

        if (!attemptingConnect.compareAndSet(/*expect*/ false, /*if false then set to*/ true)) {
            // Race for connection attempt... this thread lost.
            throw lastSeenConnectionException();
        }

        try {
            if (lastConnectionAttempt != null) {
                LOGGER.info("Connection retry interval ({} seconds) passed, " +
                    "attempting connection recovery to LDAP at {}:{}",
                    ldapConfiguration.getRetryIntervalSeconds(),
                    ldapConfiguration.getServer(),
                    ldapConfiguration.getPort());
            }

            lastConnectionAttempt = Instant.now();
            BindResult bindResult = null;

            if (!ldapConnection.isConnected()) {
                ldapConnection.connect(
                    ldapConfiguration.getServer(), ldapConfiguration.getPort());
                bindResult = ldapConnection.bind(
                    ldapConfiguration.getBindDn(), ldapConfiguration.getBindDNPwd());
            } else if (ldapConnection.getLastBindRequest() == null) {
                bindResult = ldapConnection.bind(
                    ldapConfiguration.getBindDn(), ldapConfiguration.getBindDNPwd());
            }

            if (bindResult != null && bindResult.getResultCode() != ResultCode.SUCCESS) {
                LOGGER.error("Error binding to LDAP" + bindResult.getResultCode());
                throw new LDAPException(bindResult.getResultCode(), "Error binding to LDAP");
            }

            connectionPool = new LDAPConnectionPool(ldapConnection, ldapConfiguration.getPoolSize());
            connectionPool.setMaxConnectionAgeMillis(ldapConfiguration.getPoolMaxConnectionAgeMS());

            LOGGER.info("Initialized LDAPConnectionPool: poolSize={}, poolMaxAge={}, connectionTimeout={}, responseTimeout={}, debug={}, keepAlive={}.",
                ldapConfiguration.getPoolSize(), ldapConfiguration.getPoolMaxConnectionAgeMS(), ldapConfiguration.getConnectionTimeoutMS(), ldapConfiguration.getResponseTimeoutMS(),
                ldapConfiguration.isDebug(), ldapConfiguration.isKeepAlive());
        } catch (LDAPException e) {
            connectionException = e;
            throw e;
        } finally {
            attemptingConnect.set(false);
        }
    }

    @Override
    public Set<String> getUserRoles(String username) throws Exception {
        LOGGER.debug("getRoles("+username+")");

        Objects.requireNonNull(username);

        connectIfNeeded();

        Set<String> roles = new HashSet<>();

        String filter = "(uid=" + username + ")";

        SearchRequest searchRequest = new SearchRequest(searchBase, SearchScope.SUB, filter);
        SearchResult searchResult = connectionPool.search(searchRequest);
        List<SearchResultEntry> searchResultEntries = searchResult.getSearchEntries();

        if(searchResultEntries.isEmpty()) {
            LOGGER.warn("No result found roles for user: " + username);
            return new HashSet<String>();
        } else if (searchResultEntries.size() > 1) {
            LOGGER.error("Multiples users found and only one was expected for user: " + username);
            return new HashSet<String>();
        } else {
            for(SearchResultEntry searchResultEntry : searchResultEntries) {
                String[] groups = searchResultEntry.getAttributeValues("memberOf");
                if(null != groups) {
                    for(String group : groups) {
                        for (RDN rdn : new DN(group).getRDNs()) {
                            if (rdn.hasAttribute("cn")) {
                                roles.addAll(Arrays.asList(rdn.getAttributeValues()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        return roles;
    }

    private LDAPException lastSeenConnectionException() {
        if (connectionException == null) {
            throw new IllegalStateException("Expected connection exception, but was null. There " +
                "was probably a problem connecting but the exception is unknown. Please report " +
                "this bug to maintainers: " +
                "https://github.com/esbtools/cert-ldap-login-module/issues/new");
        }

        return connectionException;
    }

    private boolean readyForConnectionAttempt() {
        if (lastConnectionAttempt == null) {
            return true;
        }

        Duration timeSinceLastAttempt = Duration.between(lastConnectionAttempt, Instant.now());
        Duration retryInterval = Duration.ofSeconds(ldapConfiguration.getRetryIntervalSeconds());

        return timeSinceLastAttempt.compareTo(retryInterval) >= 0;
    }
}
