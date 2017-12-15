package org.esbtools.auth.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.naming.NamingException;
import javax.naming.directory.NoSuchAttributeException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class EnvironmentUtilsTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test(expected = NullPointerException.class)
    public void testValidateEnvironment_NullEnvironment() throws Exception {
        new EnvironmentUtils(null);
    }

    @Test
    public void testValidateEnvironment_ValidLocation() throws Exception {
        new EnvironmentUtils("dev")
            .validateEnvironment("ou=someuser,l=dev");
    }

    @Test
    public void testValidateEnvironment_AllAccessOU() throws Exception {
        new EnvironmentUtils("dev", "allaccessou")
            .validateEnvironment("ou=allaccessou,l=notdev");
    }

    @Test
    public void testValidateEnvironment_MissingOU() throws Exception {
        expectedEx.expect(NoSuchAttributeException.class);
        expectedEx.expectMessage("No ou in dn, you may need to update your certificate: l=dev");

        new EnvironmentUtils("dev")
            .validateEnvironment("l=dev");
    }

    @Test
    public void testValidateEnvironment_MissingLocation() throws Exception {
        expectedEx.expect(NoSuchAttributeException.class);
        expectedEx.expectMessage("No location in dn, you may need to update your certificate: ou=someuser");

        new EnvironmentUtils("dev")
            .validateEnvironment("ou=someuser");
    }

    @Test
    public void testValidateEnvironment_InvalidLocation() throws Exception {
        expectedEx.expect(NoSuchAttributeException.class);
        expectedEx.expectMessage("Invalid location from dn, expected dev but found l=notdev");

        new EnvironmentUtils("dev")
            .validateEnvironment("ou=someuser,l=notdev");
    }

    @Test
    public void testGetLDAPAttribute() throws NamingException {
        assertEquals("testuser", new EnvironmentUtils("dev").getLDAPAttribute("ou=testuser,l=dev", "ou"));
    }

    @Test
    public void testGetLDAPAttribute_NotFound() throws NamingException {
        assertEquals("", new EnvironmentUtils("dev").getLDAPAttribute("ou=testuser,l=dev", "cn"));
    }

    @Test
    public void testLocationMatchesEnvironment_SingleEnvironment_True() {
        assertTrue(new EnvironmentUtils("dev").locationMatchesEnvironment("dev"));
    }

    @Test
    public void testLocationMatchesEnvironment_SingleEnvironment_False() {
        assertFalse(new EnvironmentUtils("dev").locationMatchesEnvironment("notdev"));
    }
    
    @Test
    public void testLocationMatchesEnvironment_MultipleEnvironment_True() {
        assertTrue(new EnvironmentUtils("someenv,dev,anotherenv").locationMatchesEnvironment("dev"));
    }

    @Test
    public void testLocationMatchesEnvironment_MultipleEnvironment_False() {
        assertFalse(new EnvironmentUtils("someenv,dev,anotherenv").locationMatchesEnvironment("notdev"));
    }

}
