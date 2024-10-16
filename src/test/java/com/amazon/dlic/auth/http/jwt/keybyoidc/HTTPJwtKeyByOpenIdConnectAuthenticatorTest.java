/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;

import io.jsonwebtoken.Jwts;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class HTTPJwtKeyByOpenIdConnectAuthenticatorTest {

    protected static MockIpdServer mockIdpServer;

    @BeforeClass
    public static void setUp() throws Exception {
        mockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL);
    }

    @AfterClass
    public static void tearDown() {
        if (mockIdpServer != null) {
            try {
                mockIdpServer.close();
            } catch (Exception e) {}
        }
    }

    @Test
    public void basicTest() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void jwksUriTest() {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_2), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void jwksMissingRequiredIssuerInClaimTest() {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_NO_ISSUER_OCT_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksNotMatchingRequiredIssuerInClaimTest() {
        Settings settings = Settings.builder().put("jwks_uri", mockIdpServer.getJwksUri()).put("required_issuer", "Wrong Issuer").build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_2), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksMatchAtLeastOneRequiredAudienceInClaimTest() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void jwksMissingRequiredAudienceInClaimTest() {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_NO_AUDIENCE_OCT_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksNotMatchingRequiredAudienceInClaimTest() {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_audience", "Wrong Audience")
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_2), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksUriMissingTest() {
        var exception = Assert.assertThrows(Exception.class, () -> {
            HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(Settings.builder().build(), null);
            jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
            );
        });

        assertThat(exception.getMessage(), is("Authentication backend failed"));
        assertThat(exception.getClass(), is(OpenSearchSecurityException.class));
    }

    @Test
    public void testEscapeKid() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_SIGNED_OCT_1_INVALID_KID),
                new HashMap<String, String>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void bearerTest() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<String, String>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void testRoles() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("roles_key", TestJwts.ROLES_CLAIM)
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<String, String>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getBackendRoles(), is(TestJwts.TEST_ROLES));
    }

    @Test
    public void testRolesInNestedClaim() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("roles_pointer", "/realm_access/roles")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);


        Jwts.builder().subject("Leonard McCoy").claim("realm_access", Collections.singletonMap("roles", new String[] { "role1", "role2" }));

        TestcreateSigned

        String token = TestJwts.createSigned()

        Jwts.builder().subject("Leonard McCoy").claim("realm_access", Collections.singletonMap("roles", new String[] { "role1", "role2" })).signWith(TestJwts.

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", , new HashMap<String, String>())
                .asSecurityRequest(),
            null
        );

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_pointer",
                        "/realm_access/roles"),
                Jwts.builder().subject("Leonard McCoy").claim("realm_access", Collections.singletonMap("roles", new String[] { "role1", "role2" })));

        Assert.assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(2));
        assertThat(credentials.getBackendRoles(), containsInAnyOrder("role1", "role2"));
    }

    @Test
    public void testExp() {
        Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_EXPIRED_SIGNED_OCT_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void testExpInSkew() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("jwt_clock_skew_tolerance_seconds", "10")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        long expiringDate = System.currentTimeMillis() / 1000 - 5;
        long notBeforeDate = System.currentTimeMillis() / 1000 - 25;

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
                new HashMap<>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
    }

    @Test
    public void testNbf() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("jwt_clock_skew_tolerance_seconds", "0")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        long expiringDate = 20 + System.currentTimeMillis() / 1000;
        long notBeforeDate = 5 + System.currentTimeMillis() / 1000;

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
                new HashMap<>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void testNbfInSkew() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("jwt_clock_skew_tolerance_seconds", "10")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        long expiringDate = 20 + System.currentTimeMillis() / 1000;
        long notBeforeDate = 5 + System.currentTimeMillis() / 1000;

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
                new HashMap<>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
    }

    @Test
    public void testRS256() {

        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void testBadSignature() {

        Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_X), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void testPeculiarJsonEscaping() {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.PeculiarEscaping.MC_COY_SIGNED_RSA_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

}
