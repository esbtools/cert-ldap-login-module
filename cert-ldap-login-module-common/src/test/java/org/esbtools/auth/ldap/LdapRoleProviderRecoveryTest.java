package org.esbtools.auth.ldap;

import static org.junit.Assert.fail;

import com.redhat.lightblue.ldap.test.LdapServerExternalResource;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class LdapRoleProviderRecoveryTest {
  private final LdapConfiguration ldapConfiguration = new LdapConfiguration()
      .bindDn("uid=admin,dc=com")
      .bindDNPwd("password")
      .server("localhost")
      .port(LdapServerExternalResource.DEFAULT_PORT)
      .retryIntervalSeconds(1);

  private InMemoryDirectoryServer ldapServer;

  @Before
  public void createButDoNotStartLdapServer() throws LDAPException {
    InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=com");
    config.addAdditionalBindCredentials("uid=admin,dc=com", "password");

    InMemoryListenerConfig listenerConfig = new InMemoryListenerConfig(
        "test", null, LdapServerExternalResource.DEFAULT_PORT, null, null, null);
    config.setListenerConfigs(listenerConfig);
    config.setSchema(null);

    ldapServer = new InMemoryDirectoryServer(config);

    ldapServer.add("dc=com", new Attribute("objectClass", "top"),
        new Attribute("objectClass", "domain"),
        new Attribute("dc", "com"));
  }

  @After
  public void stopLdapServer() {
    ldapServer.shutDown(true);
  }

  @Test
  public void eventuallyConnectsToLdapIfNotFailFast() throws Exception {
    LdapRolesProvider provider = null;

    try {
      provider = new LdapRolesProvider(
          LdapServerExternalResource.DEFAULT_BASE_DN,
          ldapConfiguration, false);
    } catch (LDAPException e) {
      fail("Expected not to fail fast if failFast is false but got: " + e);
    }

    try {
      provider.getUserRoles("test");
      fail("Expected exception since LDAP server is not yet started, but no exception was thrown");
    } catch (LDAPException expected) {
      // fall through
    }

    // Above should fail even if server already started due to retry interval, however it's possible
    // (if unlikely) the test could take a second before calling getUserRoles which would mean it
    // would attempt the connection, succeed, then fail the test. Thus to avoid a flakey test,
    // not testing that case exactly.
    ldapServer.startListening();

    // Wait retry interval...
    Thread.sleep(1000);

    try {
      provider.getUserRoles("test");
      // pass!
    } catch (LDAPException e) {
      fail("Expected to recover after retry interval but got: " + e);
    }
  }
}
