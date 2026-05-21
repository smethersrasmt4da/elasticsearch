/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.ml.datafeed;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.TransportSearchAction;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.ml.action.PutDatafeedAction;
import org.elasticsearch.xpack.core.ml.action.UpdateDatafeedAction;
import org.elasticsearch.xpack.core.ml.datafeed.DatafeedConfig;
import org.elasticsearch.xpack.core.ml.job.messages.Messages;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.cloud.CloudCredential;
import org.elasticsearch.xpack.core.security.cloud.CloudCredentialManager;
import org.elasticsearch.xpack.core.security.cloud.InternalCloudApiKeyService;
import org.elasticsearch.xpack.core.security.cloud.PersistedCloudCredential;
import org.elasticsearch.xpack.ml.datafeed.persistence.DatafeedConfigProvider;
import org.elasticsearch.xpack.ml.notifications.AnomalyDetectionAuditor;

import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

import static org.elasticsearch.xpack.core.ClientHelper.ML_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeWithHeadersAsync;
import static org.elasticsearch.xpack.ml.utils.SecondaryAuthorizationUtils.useSecondaryAuthIfAvailable;

/**
 * Credential transition policy and execution for CPS datafeeds: decide mint/rekey/clear/keep,
 * validate-before-mint, persist via {@link CredentialTransitions.Change}, and best-effort revoke.
 */
public final class CredentialTransitions {

    private static final Logger logger = LogManager.getLogger(CredentialTransitions.class);

    /**
     * How a datafeed config update should treat the persisted cloud internal credential envelope.
     */
    public sealed interface Change permits Change.Keep, Change.Replace, Change.Clear {

        record Keep() implements Change {}

        record Replace(PersistedCloudCredential newCredential) implements Change {}

        record Clear() implements Change {}

        Keep KEEP = new Keep();
        Clear CLEAR = new Clear();
    }

    public enum Intent {
        KEEP,
        REPLACE,
        CLEAR
    }

    public record TransitionContext(
        boolean crossProjectEnabled,
        boolean callerHasCloudCredential,
        boolean envelopeExists,
        boolean configRequiresCloudInternal,
        boolean affectsCrossProjectSearchSurface
    ) {}

    private final AnomalyDetectionAuditor auditor;
    private final Supplier<InternalCloudApiKeyService> apiKeyServiceSupplier;
    private final Supplier<CloudCredentialManager> credentialManagerSupplier;
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final DatafeedConfigProvider datafeedConfigProvider;

    public CredentialTransitions(
        AnomalyDetectionAuditor auditor,
        Supplier<InternalCloudApiKeyService> apiKeyServiceSupplier,
        Supplier<CloudCredentialManager> credentialManagerSupplier,
        Client client,
        NamedXContentRegistry xContentRegistry,
        DatafeedConfigProvider datafeedConfigProvider
    ) {
        this.auditor = auditor;
        this.apiKeyServiceSupplier = apiKeyServiceSupplier;
        this.credentialManagerSupplier = credentialManagerSupplier;
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.datafeedConfigProvider = datafeedConfigProvider;
    }

    public static Intent decideForUpdate(TransitionContext ctx) {
        if (ctx.crossProjectEnabled() == false) {
            return Intent.KEEP;
        }
        if (ctx.callerHasCloudCredential() == false && ctx.envelopeExists()) {
            return Intent.CLEAR;
        }
        if (ctx.callerHasCloudCredential()
            && ctx.configRequiresCloudInternal()
            && (ctx.envelopeExists() == false || ctx.affectsCrossProjectSearchSurface())) {
            return Intent.REPLACE;
        }
        return Intent.KEEP;
    }

    public static Intent decideForCreate(TransitionContext ctx) {
        if (ctx.crossProjectEnabled() && ctx.callerHasCloudCredential() && ctx.configRequiresCloudInternal()) {
            return Intent.REPLACE;
        }
        return Intent.KEEP;
    }

    public boolean hasCloudManagedCredential(ThreadPool threadPool) {
        return credentialManagerSupplier.get().hasCloudManagedCredential(threadPool.getThreadContext());
    }

    public void executeUpdate(
        Intent intent,
        UpdateDatafeedAction.Request request,
        DatafeedConfig merged,
        String jobId,
        Map<String, String> headers,
        ThreadPool threadPool,
        SecurityContext securityContext,
        BiConsumer<DatafeedConfig, ActionListener<Boolean>> validator,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        switch (intent) {
            case CLEAR -> applyDowngrade(request, jobId, headers, validator, listener);
            case REPLACE -> applyRekey(request, merged, jobId, threadPool, securityContext, validator, listener);
            case KEEP -> persistUpdateWithoutCredentialChange(request, headers, validator, listener);
        }
    }

    public void executePut(
        Intent intent,
        PutDatafeedAction.Request request,
        ClusterState clusterState,
        ThreadPool threadPool,
        @Nullable SecurityContext securityContext,
        PutPersistentCallback persistFn,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        if (intent == Intent.REPLACE) {
            String datafeedId = request.getDatafeed().getId();
            String jobId = request.getDatafeed().getJobId();
            Map<String, String> headers = threadPool.getThreadContext().getHeaders();
            validateSearchBeforeMint(request.getDatafeed(), headers, listener.delegateFailureAndWrap((l, ignored) -> {
                auditor.info(jobId, Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_MINTED));
                mintCpsKeyForDatafeed(datafeedId, threadPool, securityContext, l, (newCredential, userHeaders) -> {
                    DatafeedConfig.Builder builder = new DatafeedConfig.Builder(request.getDatafeed());
                    builder.setCloudInternalCredential(newCredential);
                    PutDatafeedAction.Request updatedRequest = new PutDatafeedAction.Request(builder.build());
                    updatedRequest.masterNodeTimeout(request.masterNodeTimeout());
                    persistFn.put(updatedRequest, userHeaders, clusterState, revokeKeyOnFailure(newCredential, jobId, l));
                });
            }));
        } else {
            persistFn.put(request, threadPool.getThreadContext().getHeaders(), clusterState, listener);
        }
    }

    /**
     * Best-effort revokes a persisted envelope before running {@code continuation}.
     */
    public void revokeEnvelopeIfPresent(String datafeedId, DatafeedConfig config, Runnable continuation) {
        PersistedCloudCredential cred = config.getCloudInternalCredential();
        if (cred == null) {
            continuation.run();
            return;
        }
        apiKeyServiceSupplier.get().revokeCloudAuthentication(cred, ActionListener.wrap(ignored -> {
            auditor.info(config.getJobId(), Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REVOKED));
            cred.close();
            continuation.run();
        }, e -> {
            logger.warn(() -> "[" + datafeedId + "] Failed to revoke internal cloud API key [" + cred.id() + "] on datafeed delete", e);
            auditor.info(config.getJobId(), Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REVOCATION_FAILED, cred.id()));
            cred.close();
            continuation.run();
        }));
    }

    @FunctionalInterface
    public interface PutPersistentCallback {
        void put(
            PutDatafeedAction.Request request,
            Map<String, String> headers,
            ClusterState clusterState,
            ActionListener<PutDatafeedAction.Response> listener
        );
    }

    private void persistUpdateWithoutCredentialChange(
        UpdateDatafeedAction.Request request,
        Map<String, String> headers,
        BiConsumer<DatafeedConfig, ActionListener<Boolean>> validator,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        datafeedConfigProvider.updateDatefeedConfig(
            request.getUpdate().getId(),
            request.getUpdate(),
            headers,
            validator,
            listener.delegateFailureAndWrap((l, updatedConfig) -> l.onResponse(new PutDatafeedAction.Response(updatedConfig)))
        );
    }

    private void applyDowngrade(
        UpdateDatafeedAction.Request request,
        String jobId,
        Map<String, String> headers,
        BiConsumer<DatafeedConfig, ActionListener<Boolean>> validator,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        String datafeedId = request.getUpdate().getId();
        datafeedConfigProvider.updateDatefeedConfig(
            datafeedId,
            request.getUpdate(),
            headers,
            Change.CLEAR,
            validator,
            listener.delegateFailureAndWrap((l, tuple) -> {
                auditor.info(jobId, Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_CLEARED));
                DatafeedConfig updatedConfig = tuple.v1();
                PersistedCloudCredential oldCredential = tuple.v2();
                if (oldCredential != null) {
                    bestEffortRevokeOldKey(datafeedId, oldCredential, updatedConfig, l);
                } else {
                    l.onResponse(new PutDatafeedAction.Response(updatedConfig));
                }
            })
        );
    }

    private void applyRekey(
        UpdateDatafeedAction.Request request,
        DatafeedConfig merged,
        String jobId,
        ThreadPool threadPool,
        SecurityContext securityContext,
        BiConsumer<DatafeedConfig, ActionListener<Boolean>> validator,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        String datafeedId = request.getUpdate().getId();
        Map<String, String> headers = threadPool.getThreadContext().getHeaders();
        validateSearchBeforeMint(
            merged,
            headers,
            listener.delegateFailureAndWrap(
                (l, ignored) -> mintCpsKeyForDatafeed(datafeedId, threadPool, securityContext, l, (newCredential, userHeaders) -> {
                    auditor.info(jobId, Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REKEYED));
                    ActionListener<PutDatafeedAction.Response> guardedListener = revokeKeyOnFailure(newCredential, jobId, l);
                    datafeedConfigProvider.updateDatefeedConfig(
                        datafeedId,
                        request.getUpdate(),
                        userHeaders,
                        new Change.Replace(newCredential),
                        validator,
                        guardedListener.delegateFailureAndWrap((ll, tuple) -> finalizeRekey(datafeedId, tuple, ll))
                    );
                })
            )
        );
    }

    private void finalizeRekey(
        String datafeedId,
        Tuple<DatafeedConfig, PersistedCloudCredential> tuple,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        DatafeedConfig updatedConfig = tuple.v1();
        PersistedCloudCredential oldCredential = tuple.v2();
        if (oldCredential != null) {
            bestEffortRevokeOldKey(datafeedId, oldCredential, updatedConfig, listener);
        } else {
            listener.onResponse(new PutDatafeedAction.Response(updatedConfig));
        }
    }

    private void bestEffortRevokeOldKey(
        String datafeedId,
        PersistedCloudCredential oldCredential,
        DatafeedConfig patchedConfig,
        ActionListener<PutDatafeedAction.Response> listener
    ) {
        apiKeyServiceSupplier.get().revokeCloudAuthentication(oldCredential, ActionListener.wrap(ignored -> {
            auditor.info(patchedConfig.getJobId(), Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REVOKED));
            oldCredential.close();
            listener.onResponse(new PutDatafeedAction.Response(patchedConfig));
        }, e -> {
            logger.warn(() -> "[" + datafeedId + "] Failed to revoke superseded internal cloud API key [" + oldCredential.id() + "]", e);
            auditor.info(
                patchedConfig.getJobId(),
                Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REVOCATION_FAILED, oldCredential.id())
            );
            oldCredential.close();
            listener.onResponse(new PutDatafeedAction.Response(patchedConfig));
        }));
    }

    private void validateSearchBeforeMint(DatafeedConfig config, Map<String, String> headers, ActionListener<Void> listener) {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder().size(0);
        QueryBuilder query = config.getParsedQuery(xContentRegistry);
        if (query != null) {
            sourceBuilder.query(query);
        }
        if (config.getRuntimeMappings() != null && config.getRuntimeMappings().isEmpty() == false) {
            sourceBuilder.runtimeMappings(config.getRuntimeMappings());
        }
        SearchRequest searchRequest = new SearchRequest(config.getIndices().toArray(String[]::new)).indicesOptions(
            config.getIndicesOptions()
        ).source(sourceBuilder);
        if (config.getProjectRouting() != null) {
            searchRequest.setProjectRouting(config.getProjectRouting());
        }
        executeWithHeadersAsync(
            headers,
            ML_ORIGIN,
            client,
            TransportSearchAction.TYPE,
            true,
            searchRequest,
            listener.delegateFailureAndWrap((l, response) -> {
                if (response == null) {
                    l.onFailure(
                        new ElasticsearchStatusException(
                            "Unexpected null response from datafeed search probe",
                            RestStatus.INTERNAL_SERVER_ERROR
                        )
                    );
                    return;
                }
                if (response.status() != RestStatus.OK) {
                    l.onFailure(
                        new ElasticsearchStatusException(
                            "Datafeed search probe failed with status [" + response.status() + "]",
                            response.status()
                        )
                    );
                    return;
                }
                l.onResponse(null);
            })
        );
    }

    private void mintCpsKeyForDatafeed(
        String datafeedId,
        ThreadPool threadPool,
        @Nullable SecurityContext securityContext,
        ActionListener<?> failurePropagator,
        BiConsumer<PersistedCloudCredential, Map<String, String>> onSuccess
    ) {
        useSecondaryAuthIfAvailable(securityContext, () -> {
            CloudCredential callerCredential = credentialManagerSupplier.get().extractCloudManagedCredential(threadPool.getThreadContext());
            Map<String, String> userHeaders = threadPool.getThreadContext().getHeaders();
            apiKeyServiceSupplier.get()
                .grantCloudAuthentication(
                    callerCredential,
                    "datafeed:" + datafeedId,
                    ActionListener.wrap(
                        result -> useSecondaryAuthIfAvailable(
                            securityContext,
                            () -> onSuccess.accept(result.persistedCredential(), userHeaders)
                        ),
                        e -> {
                            logger.error(() -> "[" + datafeedId + "] Failed to mint internal cloud API key for CPS datafeed", e);
                            failurePropagator.onFailure(e);
                        }
                    )
                );
        });
    }

    private <T> ActionListener<T> revokeKeyOnFailure(PersistedCloudCredential mintedCredential, String jobId, ActionListener<T> delegate) {
        return ActionListener.wrap(
            delegate::onResponse,
            e -> apiKeyServiceSupplier.get().revokeCloudAuthentication(mintedCredential, ActionListener.wrap(ignored -> {
                auditor.info(jobId, Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REVOKED));
                mintedCredential.close();
                delegate.onFailure(e);
            }, revokeFailure -> {
                auditor.info(jobId, Messages.getMessage(Messages.JOB_AUDIT_DATAFEED_CPS_KEY_REVOCATION_FAILED, mintedCredential.id()));
                mintedCredential.close();
                delegate.onFailure(e);
            }))
        );
    }
}
