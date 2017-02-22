/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2017] VMware, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.client.MultitenantClientDetailsService;
import org.cloudfoundry.identity.uaa.client.VmidentityDataAccessException;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.Assert;

import com.google.common.primitives.Ints;
import com.vmware.identity.idm.DuplicatedOIDCClientException;
import com.vmware.identity.idm.DuplicatedOIDCRedirectURLException;
import com.vmware.identity.idm.NoSuchOIDCClientException;
import com.vmware.identity.idm.OIDCClient;
import com.vmware.identity.idm.client.CasIdmClient;

public class MultitenantVmidentityClientDetailsService implements MultitenantClientDetailsService {

    private static final Log logger = LogFactory.getLog(MultitenantVmidentityClientDetailsService.class);

    private final CasIdmClient idmClient;
    private final PasswordEncoder passwordEncoder;

    public MultitenantVmidentityClientDetailsService(CasIdmClient idmClient, PasswordEncoder passwordEncoder) throws NoSuchAlgorithmException {
        Assert.notNull(idmClient, "CasIdmClient required");
        this.idmClient = idmClient;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            // Encode password here...
            OIDCClient client = mapClientDetails(clientDetails, passwordEncoder);
            idmClient.addOIDCClient(tenant, client);
        } catch (DuplicatedOIDCClientException e) {
            logger.error("Client with ID already exists: " + clientDetails.getClientId(), e);
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId());
        } catch (DuplicatedOIDCRedirectURLException e) {
            logger.error("Client with registered redirect already exists: " + clientDetails.getRegisteredRedirectUri(), e);
            throw new ClientAlreadyExistsException("Client with registered redirect already exists: " + clientDetails.getRegisteredRedirectUri());
        } catch (Exception e) {
            logger.error("Unable to add client details", e);
            throw new VmidentityDataAccessException("Unable to add client details");
        }

    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            // TODO Skip password encoding...
            OIDCClient client = mapClientDetails(clientDetails, passwordEncoder);
            idmClient.setOIDCClient(tenant, client);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id: " + clientDetails.getClientId() + " in identity zone " + IdentityZoneHolder.get().getName(), e);
            throw new NoSuchClientException("No client found with id = " + clientDetails.getClientId() + " in identity zone " + IdentityZoneHolder.get().getName());
        } catch (Exception e) {
            logger.error("Unable to update client details with id: " + clientDetails.getClientId(), e);
            throw new VmidentityDataAccessException("Unable to update client details");
        }
    }

    @Override
    public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        // TODO Auto-generated method stub

    }

    @Override
    public void removeClientDetails(String clientId) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            idmClient.deleteOIDCClient(tenant, clientId);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id = " + clientId, e);
            throw new NoSuchClientException("No client found with id = " + clientId);
        } catch (Exception e) {
            logger.error("Unable to remove client details with id = " + clientId, e);
            throw new VmidentityDataAccessException("Unable to remvoe client details");
        }
    }

    @Override
    public List<ClientDetails> listClientDetails() {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);

            List<ClientDetails> details = new ArrayList<ClientDetails>(clients.size());
            for (OIDCClient client : clients) {
                details.add(mapOIDCClient(client, tenant, idmClient, passwordEncoder));
            }

            return details;
        } catch (Exception e) {
            logger.error("Unable to list client details for identity zone: " + IdentityZoneHolder.get().getName(), e);
            throw new VmidentityDataAccessException("Unable to list client details");
        }
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        ClientDetails details;

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            details = mapOIDCClient(idmClient.getOIDCClient(tenant, clientId), tenant, idmClient, passwordEncoder);
        } catch (NoSuchOIDCClientException e) {
            logger.error("Unable to load client with id: " + clientId, e);
            throw new NoSuchClientException("No client with requested id: " + clientId);
        } catch (Exception e) {
            logger.error("An error occurred loading client with id: " + clientId, e);
            throw new VmidentityDataAccessException("Unable to load client with id: " + clientId);
        }

        return details;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        try {
            String tenant = VmidentityUtils.getTenantName(zoneId, idmClient);
            Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);

            for (OIDCClient client : clients) {
                idmClient.deleteOIDCClient(tenant, client.getClientId());
            }

            return clients.size();
        } catch (Exception e) {
            logger.error("Unable to delete clients for identity zone: " + zoneId, e);
            throw new VmidentityDataAccessException("Unable to delete clients for identity zone: " + zoneId);
        }
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public Log getLogger() {
        return logger;
    }

    @Override
    public int getTotalCount() {
        try {
            int count = 0;
            Collection<String> tenants = idmClient.getAllTenants();

            for (String tenant : tenants) {
                Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);
                count += clients.size();
            }

            return count;
        } catch (Exception e) {
            logger.error("Unable to enumerate clients", e);
            throw new VmidentityDataAccessException("Unable to enumerate clients");
        }
    }

    @Override
    public void addClientSecret(String clientId, String newSecret) throws NoSuchClientException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deleteClientSecret(String clientId) throws NoSuchClientException {
        // TODO Auto-generated method stub

    }

    private static List<String> authoritiesToListOfStrings(Collection<GrantedAuthority> authorities) {
        List<String> stringAuthorities = new ArrayList<String>(authorities.size());

        for (GrantedAuthority authority : authorities) {
            stringAuthorities.add(authority.getAuthority());
        }

        return stringAuthorities;
    }

    private static OIDCClient mapClientDetails(ClientDetails details, PasswordEncoder passwordEncoder) {
        OIDCClient.Builder builder = new OIDCClient.Builder(details.getClientId());
        ArrayList<String> redirectUris = new ArrayList<String>();
        if (details.getRegisteredRedirectUri() != null) {
            redirectUris.addAll(details.getRegisteredRedirectUri());
        }
        builder.redirectUris(redirectUris);
        // builder.resourceIds(details.getResourceIds()); TODO resource IDs
        // builder.scope(details.getScope()); TODO scope
        // builder.authorizedGrantTypes(details.getAuthorizedGrantTypes()); TODO grant types
        builder.authorities(authoritiesToListOfStrings(details.getAuthorities()));

        // builder.accessTokenValiditySeconds(details.getAccessTokenValiditySeconds()); TODO access token validity
        // builder.refreshTokenValiditySeconds(details.getRefreshTokenValiditySeconds()); TODO refresh token validity

        if (details.getClientSecret() != null) {
            builder.clientSecret(passwordEncoder.encode(details.getClientSecret()));
        }
        // TODO Auto Approve Scopes
        // Set<String> autoApproveScopes = new HashSet<String>();
        // Map<String, Object> additionalInformation = details.getAdditionalInformation();
        // Object autoApprovedFromAddInfo = additionalInformation.remove(ClientConstants.AUTO_APPROVE);
        // if (autoApprovedFromAddInfo != null) {
        //    if ((autoApprovedFromAddInfo instanceof Boolean && (Boolean) autoApprovedFromAddInfo || "true".equals(autoApprovedFromAddInfo))) {
        //        autoApproveScopes.add("true");
        //    } else if (autoApprovedFromAddInfo instanceof Collection<?>) {
        //        @SuppressWarnings("unchecked")
        //        Collection<? extends String> approvedScopes = (Collection<? extends String>) autoApprovedFromAddInfo;
        //        autoApproveScopes.addAll(approvedScopes);
        //    }
        // }
        // builder.autoApproveScopes(autoApproveScopes);
        //
        // TODO lastModified
        // Object timestamp = additionalInformation.remove("lastModified");
        // if (timestamp != null) {
        //    if (timestamp instanceof Timestamp) {
        //       builder.lastModified((Timestamp) timestamp);
        //    }
        // }

        return builder.build();
    }

    private static ClientDetails mapOIDCClient(OIDCClient client, String tenant, CasIdmClient idmClient, PasswordEncoder passwordEncoder) throws Exception {
        BaseClientDetails details = new BaseClientDetails();
        details.setClientId(client.getClientId());
        details.setClientSecret(client.getClientSecret()); // TODO client secret
        // details.setResourceIds(client.getResourceIds()); TODO resource IDs
        // details.setScope(Arrays.asList(new String[] { "uaa.none" })); // TODO Scope
        // details.setAuthorizedGrantTypes(Arrays.asList(new String[] { "client_credentials" })); // TODO Grant types
        if (client.getAuthorities() != null) {
            details.setAuthorities(AuthorityUtils.createAuthorityList(client.getAuthorities().toArray(new String[0])));
        }
        details.setRegisteredRedirectUri(new HashSet<String>(client.getRedirectUris()));
        details.setAccessTokenValiditySeconds(
                Ints.saturatedCast(idmClient.getMaximumBearerTokenLifetime(tenant) / 1000));
        details.setRefreshTokenValiditySeconds(
                Ints.saturatedCast(idmClient.getMaximumBearerRefreshTokenLifetime(tenant) / 1000));

        details.setAutoApproveScopes(Arrays.asList(new String[] { "true" })); // TODO auto approve scopes
        // details.addAdditionalInformation("lastModified", client.getLastModified()); TODO last modified

        return details;
    }



}
