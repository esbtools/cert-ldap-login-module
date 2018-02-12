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


public class LdapConfiguration {

    private String server;
    private Integer port;
    private String bindDn;
    private String bindDNPwd;
    private Boolean useSSL = false;
    private String trustStore;
    private String trustStorePassword;
    private Integer poolSize = 5;
    private Integer poolMaxConnectionAgeMS = 15000; // re-estabilish connection in the pool after that time
    private Integer connectionTimeoutMS = 3000; // time to wait to estabilish connection
    private Integer responseTimeoutMS = 3000; // time to wait until receiving response from ldap
    private boolean debug = false;
    private boolean keepAlive = true;
    private Integer retryIntervalSeconds = 5;

    public LdapConfiguration server (String server) {
        this.server = server;
        return this;
    }

    public LdapConfiguration port (Integer port) {
        this.port = port;
        return this;
    }

    public LdapConfiguration bindDn (String bindDn) {
        this.bindDn = bindDn;
        return this;
    }

    public LdapConfiguration bindDNPwd (String bindDNPwd) {
        this.bindDNPwd = bindDNPwd;
        return this;
    }

    public LdapConfiguration useSSL (Boolean useSSL) {
        this.useSSL = useSSL;
        return this;
    }

    public LdapConfiguration trustStore (String trustStore) {
        this.trustStore = trustStore;
        return this;
    }

    public LdapConfiguration trustStorePassword (String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
        return this;
    }

    public LdapConfiguration poolSize (Integer poolSize) {
        this.poolSize = poolSize;
        return this;
    }

    public String getServer() {
        return server;
    }

    public Integer getPort() {
        return port;
    }

    public String getBindDn() {
        return bindDn;
    }

    public String getBindDNPwd() {
        return bindDNPwd;
    }

    public Boolean getUseSSL() {
        return useSSL;
    }

    public String getTrustStore() {
        return trustStore;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public Integer getPoolSize() {
        return poolSize;
    }

    public Integer getConnectionTimeoutMS() {
        return connectionTimeoutMS;
    }

    public LdapConfiguration connectionTimeoutMS(Integer connectionTimeoutMS) {
        this.connectionTimeoutMS = connectionTimeoutMS;
        return this;
    }

    public Integer getResponseTimeoutMS() {
        return responseTimeoutMS;
    }

    public LdapConfiguration responseTimeoutMS(Integer responseTimeoutMS) {
        this.responseTimeoutMS = responseTimeoutMS;
        return this;
    }

    public boolean isDebug() {
        return debug;
    }

    public LdapConfiguration debug(boolean debug) {
        this.debug = debug;
        return this;
    }

    public boolean isKeepAlive() {
        return keepAlive;
    }

    public LdapConfiguration keepAlive(boolean keepAlive) {
        this.keepAlive = keepAlive;
        return this;
    }

    public Integer getPoolMaxConnectionAgeMS() {
        return poolMaxConnectionAgeMS;
    }

    public LdapConfiguration poolMaxConnectionAgeMS(Integer poolMaxConnectionAgeMS) {
        this.poolMaxConnectionAgeMS = poolMaxConnectionAgeMS;
        return this;
    }

    public Integer getRetryIntervalSeconds() {
        return retryIntervalSeconds;
    }

    public LdapConfiguration retryIntervalSeconds(Integer retryIntervalSeconds) {
        this.retryIntervalSeconds = retryIntervalSeconds;
        return this;
    }

    @Override
    public String toString() {
        return "LdapConfiguration{" +
            "server='" + server + '\'' +
            ", port=" + port +
            ", bindDn='" + bindDn + '\'' +
            ", useSSL=" + useSSL +
            ", trustStore='" + trustStore + '\'' +
            ", poolSize=" + poolSize +
            ", poolMaxConnectionAgeMS=" + poolMaxConnectionAgeMS +
            ", connectionTimeoutMS=" + connectionTimeoutMS +
            ", responseTimeoutMS=" + responseTimeoutMS +
            ", debug=" + debug +
            ", keepAlive=" + keepAlive +
            ", retryIntervalSeconds=" + retryIntervalSeconds +
            '}';
    }

    public void setServer(String server) {
      this.server = server;
    }

    public void setPort(Integer port) {
      this.port = port;
    }

    public void setBindDn(String bindDn) {
      this.bindDn = bindDn;
    }

    public void setBindDNPwd(String bindDNPwd) {
      this.bindDNPwd = bindDNPwd;
    }

    public void setUseSSL(Boolean useSSL) {
      this.useSSL = useSSL;
    }

    public void setTrustStore(String trustStore) {
      this.trustStore = trustStore;
    }

    public void setTrustStorePassword(String trustStorePassword) {
      this.trustStorePassword = trustStorePassword;
    }

    public void setPoolSize(Integer poolSize) {
      this.poolSize = poolSize;
    }

    public void setPoolMaxConnectionAgeMS(Integer poolMaxConnectionAgeMS) {
      this.poolMaxConnectionAgeMS = poolMaxConnectionAgeMS;
    }

    public void setConnectionTimeoutMS(Integer connectionTimeoutMS) {
      this.connectionTimeoutMS = connectionTimeoutMS;
    }

    public void setResponseTimeoutMS(Integer responseTimeoutMS) {
      this.responseTimeoutMS = responseTimeoutMS;
    }

    public void setDebug(boolean debug) {
      this.debug = debug;
    }

    public void setKeepAlive(boolean keepAlive) {
      this.keepAlive = keepAlive;
    }

    public void setRetryIntervalSeconds(Integer retryIntervalSeconds) {
      this.retryIntervalSeconds = retryIntervalSeconds;
    }
}
