package org.esbtools.auth.util;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import javax.naming.NamingException;
import javax.naming.directory.NoSuchAttributeException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Environment {

    private final Logger LOGGER = LoggerFactory.getLogger(Environment.class);

    public static final String ENVIRONMENT_SEPARATOR = ",";
    public static final String LOCATION = "l";
    public static final String OU = "ou";

    private final String environment;
    private final String allAccessOu;

    public String getEnvironment() {
        return environment;
    }

    public String getAllAccessOu() {
        return allAccessOu;
    }

    public Environment(String environment) {
        this(environment, null);
    }

    public Environment(String environment, String allAccessOu) {
        Objects.requireNonNull(environment);

        this.environment = environment;
        this.allAccessOu = allAccessOu;
    }

    public void validate(String certificatePrincipal) throws NamingException {

        String ou = getLDAPAttribute(certificatePrincipal, OU);
        LOGGER.debug("OU from certificate: ", ou);
        String location = getLDAPAttribute(certificatePrincipal, LOCATION);
        LOGGER.debug("Location from certificate: ", location);

        if(StringUtils.isBlank(ou)) {
            throw new NoSuchAttributeException("No ou in dn, you may need to update your certificate: " + certificatePrincipal);
        } else {
            if(getAllAccessOu() != null && getAllAccessOu().equalsIgnoreCase(StringUtils.replace(ou, " ", ""))){
                LOGGER.debug("Skipping environment validation, user ou matches {} ", getAllAccessOu());
            } else {
                //if dn not from allAccessOu, verify the location (l) field
                //in the cert matches the configured environment
                if(StringUtils.isBlank(location)) {
                    throw new NoSuchAttributeException("No location in dn, you may need to update your certificate: " + certificatePrincipal);
                } else if(!locationMatchesEnvironment(location)){
                    throw new NoSuchAttributeException("Invalid location from dn, expected " + getEnvironment() + " but found l=" + location);
                }
            }
        }
    }

    public String getLDAPAttribute(String certificatePrincipal, String searchAttribute) throws NamingException {
        String searchName = new String();
        LdapName name = new LdapName(certificatePrincipal);
        for (Rdn rdn : name.getRdns()) {
            if (rdn.getType().equalsIgnoreCase(searchAttribute)) {
                searchName = (String) rdn.getValue();
                break;
            }
        }
        return searchName;
    }

    public boolean locationMatchesEnvironment(String location) {
        List<String> environments;
        if(getEnvironment().contains(ENVIRONMENT_SEPARATOR)) {
            environments = Arrays.asList(getEnvironment().split(ENVIRONMENT_SEPARATOR));

        } else {
            environments = Arrays.asList(new String[] {getEnvironment()});
        }
        for(String environment : environments) {
            if(environment.equalsIgnoreCase(location)) {
                return true;
            }
        }
        return false;
    }

}
