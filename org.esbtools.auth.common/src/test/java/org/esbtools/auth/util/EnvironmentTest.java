package org.esbtools.auth.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.naming.NamingException;
import javax.naming.directory.NoSuchAttributeException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class EnvironmentTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    public void testValidate_NullEnvironment() throws Exception {
        new Environment(null)
            .validate("ou=someuser,l=dev");
    }
    
    @Test
    public void testValidate_EmptyEnvironment() throws Exception {
        new Environment("")
            .validate("ou=someuser,l=dev");
    }

    @Test
    public void testValidate_ValidLocation() throws Exception {
        new Environment("dev")
            .validate("ou=someuser,l=dev");
    }

    @Test
    public void testValidate_AllAccessOU() throws Exception {
        new Environment("dev", "allaccessou")
            .validate("ou=allaccessou,l=notdev");
    }

    @Test
    public void testValidate_MissingOU() throws Exception {
        expectedEx.expect(NoSuchAttributeException.class);
        expectedEx.expectMessage("No ou in dn, you may need to update your certificate: l=dev");

        new Environment("dev")
            .validate("l=dev");
    }

    @Test
    public void testValidate_MissingLocation() throws Exception {
        expectedEx.expect(NoSuchAttributeException.class);
        expectedEx.expectMessage("No location in dn, you may need to update your certificate: ou=someuser");

        new Environment("dev")
            .validate("ou=someuser");
    }

    @Test
    public void testValidate_InvalidLocation() throws Exception {
        expectedEx.expect(NoSuchAttributeException.class);
        expectedEx.expectMessage("Invalid location from dn, expected dev but found l=notdev");

        new Environment("dev")
            .validate("ou=someuser,l=notdev");
    }

    @Test
    public void testGetLDAPAttribute() throws NamingException {
        assertEquals("testuser", new Environment("dev").getLDAPAttribute("ou=testuser,l=dev", "ou"));
    }

    @Test
    public void testGetLDAPAttribute_NotFound() throws NamingException {
        assertEquals("", new Environment("dev").getLDAPAttribute("ou=testuser,l=dev", "cn"));
    }

    @Test
    public void testLocationMatchesEnvironment_SingleEnvironment_True() {
        assertTrue(new Environment("dev").locationMatchesEnvironment("dev"));
    }

    @Test
    public void testLocationMatchesEnvironment_SingleEnvironment_False() {
        assertFalse(new Environment("dev").locationMatchesEnvironment("notdev"));
    }

    @Test
    public void testLocationMatchesEnvironment_MultipleEnvironment_True() {
        assertTrue(new Environment("someenv,dev,anotherenv").locationMatchesEnvironment("dev"));
    }

    @Test
    public void testLocationMatchesEnvironment_MultipleEnvironment_False() {
        assertFalse(new Environment("someenv,dev,anotherenv").locationMatchesEnvironment("notdev"));
    }

}
