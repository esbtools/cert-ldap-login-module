package org.esbtools.auth.servlet;

import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;
import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class CertEnvironmentVerificationFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    private X509Certificate createCertificate(final String dn) {
        X509Certificate certificate = Mockito.spy(X509Certificate.class);
        Mockito.when(certificate.getSubjectDN()).thenReturn(new Principal() {

            @Override
            public String getName() {
                return dn;
            }

        });

        return certificate;
    }

    @Test
    public void nullEnvironmentShouldSkipCheck() throws Exception {
        new CertEnvironmentVerificationFilter(null).doFilter(request, response, chain);

        Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    }

    @Test
    public void noCertChainShouldSkipCheck() throws Exception {
        new CertEnvironmentVerificationFilter("fakeenv").doFilter(request, response, chain);

        Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    }

    @Test
    public void emptyCertChainShouldSkipCheck() throws Exception {
        Mockito.when(request.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(new X509Certificate[0]);

        new CertEnvironmentVerificationFilter("fakeenv").doFilter(request, response, chain);

        Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    }

    @Test
    public void certWithCorrectEnvironmentShouldPass() throws Exception {
        X509Certificate certificate = createCertificate("ou=fakeuser,l=fakeenv");
        Mockito.when(request.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(new X509Certificate[] {
                certificate
        });

        new CertEnvironmentVerificationFilter("fakeenv").doFilter(request, response, chain);

        Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    }

    @Test
    public void certWithWrongEnvironmentShouldFail() throws Exception {
        X509Certificate certificate = createCertificate("ou=fakeuser,l=fakeenv");
        Mockito.when(request.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(new X509Certificate[] {
                certificate
        });
        PrintWriter writer = Mockito.mock(PrintWriter.class);
        Mockito.when(response.getWriter()).thenReturn(writer);

        new CertEnvironmentVerificationFilter("notfakeenv").doFilter(request, response, chain);

        Mockito.verify(response, Mockito.times(1)).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        ArgumentCaptor<String> errorMsgCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(writer, Mockito.times(1)).write(errorMsgCaptor.capture());
        assertTrue(errorMsgCaptor.getValue().contains("Error"));
        Mockito.verify(chain, Mockito.never()).doFilter(request, response);
    }

}
