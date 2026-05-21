/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.ml.datafeed;

import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.cloud.PersistedCloudCredential;
import org.elasticsearch.xpack.ml.datafeed.CredentialTransitions.Change;
import org.elasticsearch.xpack.ml.datafeed.CredentialTransitions.Intent;
import org.elasticsearch.xpack.ml.datafeed.CredentialTransitions.TransitionContext;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;

public class CredentialTransitionsTests extends ESTestCase {

    private static TransitionContext ctx(
        boolean crossProjectEnabled,
        boolean callerHasCloudCredential,
        boolean envelopeExists,
        boolean affectsCrossProjectSearchSurface
    ) {
        return new TransitionContext(crossProjectEnabled, callerHasCloudCredential, envelopeExists, affectsCrossProjectSearchSurface);
    }

    public void testCpsDisabledShouldDecideKeep() {
        assertThat(CredentialTransitions.decideForUpdate(ctx(false, true, true, true)), equalTo(Intent.KEEP));
    }

    public void testNoCloudCallerWithEnvelopeShouldDecideClear() {
        assertThat(CredentialTransitions.decideForUpdate(ctx(true, false, true, false)), equalTo(Intent.CLEAR));
    }

    public void testNoCloudCallerWithoutEnvelopeShouldDecideKeep() {
        assertThat(CredentialTransitions.decideForUpdate(ctx(true, false, false, true)), equalTo(Intent.KEEP));
    }

    public void testCloudCallerOnConfigRequiringInternalWithoutEnvelopeShouldDecideReplace() {
        assertThat(CredentialTransitions.decideForUpdate(ctx(true, true, false, false)), equalTo(Intent.REPLACE));
    }

    public void testCloudCallerOnConfigRequiringInternalWithEnvelopeNoSurfaceChangeShouldDecideKeep() {
        assertThat(CredentialTransitions.decideForUpdate(ctx(true, true, true, false)), equalTo(Intent.KEEP));
    }

    public void testCloudCallerOnConfigRequiringInternalWithEnvelopeAndSurfaceChangeShouldDecideReplace() {
        assertThat(CredentialTransitions.decideForUpdate(ctx(true, true, true, true)), equalTo(Intent.REPLACE));
    }

    public void testCreateWithCpsDisabledShouldDecideKeep() {
        assertThat(CredentialTransitions.decideForCreate(ctx(false, true, false, false)), equalTo(Intent.KEEP));
    }

    public void testCreateWithNoCloudCallerShouldDecideKeep() {
        assertThat(CredentialTransitions.decideForCreate(ctx(true, false, false, false)), equalTo(Intent.KEEP));
    }

    public void testCreateWithCloudCallerAndCpsEnabledShouldDecideReplace() {
        assertThat(CredentialTransitions.decideForCreate(ctx(true, true, false, false)), equalTo(Intent.REPLACE));
    }

    public void testKeepAndClearAreSingletons() {
        assertThat(Change.KEEP, sameInstance(Change.KEEP));
        assertThat(Change.CLEAR, sameInstance(Change.CLEAR));
    }

    public void testReplaceShouldHoldCredential() {
        PersistedCloudCredential credential = new PersistedCloudCredential("key-id", new SecureString("secret".toCharArray()));
        Change.Replace replace = new Change.Replace(credential);
        assertThat(replace.newCredential(), equalTo(credential));
    }
}
