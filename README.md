# How to configure auntn/authz on JBoss

In standalone.xml:

```
<subsystem xmlns="urn:jboss:domain:security:1.2">
 <security-domain name="esbtools-cert">
	<authentication>
		<login-module name="CertLdapLoginModule" code="org.esbtools.auth.jboss.CertLdapLoginModule" flag="required">
			<module-option name="password-stacking" value="useFirstPass"/>
			<module-option name="securityDomain" value="esbtools-cert"/>
			<module-option name="verifier" value="org.jboss.security.auth.certs.AnyCertVerifier"/>
			<module-option name="authRoleName" value="authenticated"/>
			<module-option name="ldapServer" value="<ldap hostname>"/>
			<module-option name="port" value="636"/>
			<module-option name="searchBase" value="ou=example,dc=esbtools,dc=org"/>
			<module-option name="bindDn" value="uid=esbtools-app,ou=example,dc=esbtools,dc=org"/>
			<module-option name="bindPassword" value="<password>"/>
			<module-option name="useSSL" value="true"/>
			<module-option name="poolSize" value="5"/>
			<module-option name="trustStore" value="${jboss.server.config.dir}/truststore.jks"/>
			<module-option name="trustStorePassword" value="<password>"/>
		</login-module>
	</authentication>
	<jsse keystore-password="<password>" keystore-url="file://${jboss.server.config.dir}/keystore.jks" truststore-password="<password>" truststore-url="file://${jboss.server.config.dir}/truststore.jks" client-auth="true"/>
  </security-domain>
</subsystem>
```
