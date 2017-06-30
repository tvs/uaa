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
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import com.vmware.identity.idm.IDMLoginException;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

    private final Log logger = LogFactory.getLog(VmidentityAuthenticationManager.class);
    private final CasIdmClient idmClient;
    private ApplicationEventPublisher eventPublisher;
    private final List<GrantedAuthority> defaultAuthorities;

    public VmidentityAuthenticationManager(CasIdmClient idmClient, Set<String> defaultAuthorities) {
        this.idmClient = idmClient;
        this.defaultAuthorities = Collections.unmodifiableList(
                AuthorityUtils.createAuthorityList(defaultAuthorities.toArray(new String[0])));
    }

    @Override
    public Authentication authenticate(Authentication req) throws AuthenticationException {
        logger.debug("Processing authentication request for " + req.getName());

        if (req.getCredentials() == null) {
            logger.info("No credentials supplied.");
            BadCredentialsException e = new BadCredentialsException("No password supplied");
            publish(new AuthenticationFailureBadCredentialsEvent(req, e));
            throw e;
        }

        String tenant;
        String systemDomain;
        try {
            tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
        } catch (Exception ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }

        PrincipalId userId;
        try {
            userId = this.idmClient.authenticate(tenant, req.getName(), req.getCredentials().toString());
        } catch (com.vmware.identity.idm.PasswordExpiredException ex) {
            logger.warn("Account locked for user '" + req.getName() + "'.", ex);
            AuthenticationPolicyRejectionException e = new AuthenticationPolicyRejectionException(
                    "Your account has been locked.", ex);
            publish(new AuthenticationFailureCredentialsExpiredEvent(req, e));
            throw e;
        } catch (com.vmware.identity.idm.UserAccountLockedException ex) {
            logger.warn("Account locked for user '" + req.getName() + "'.", ex);
            AuthenticationPolicyRejectionException e = new AuthenticationPolicyRejectionException(
                    "Your account has been locked.", ex);
            publish(new AuthenticationFailureLockedEvent(req, e));
            throw e;
        } catch (IDMLoginException ex) {
            logger.debug("Login failed for user " + req.getName(), ex);
            BadCredentialsException e = new BadCredentialsException("Authentication failed for user " + req.getName(),
                    ex);
            publish(new AuthenticationFailureBadCredentialsEvent(req, e));
            throw e;
        } catch (Exception ex) {
            logger.warn("Auth failed for user '" + req.getName() + "'.", ex);
            AuthenticationServiceException e = new AuthenticationServiceException(ex.getMessage());
            publish(new AuthenticationFailureServiceExceptionEvent(req, e));
            throw e;
        }

        String origin;
        try {
            origin = VmidentityUtils.getOriginForDomain(tenant, userId.getDomain(), systemDomain, this.idmClient);
        } catch (Exception ex) {
            logger.error("Unable to fetch an origin for the user '" + userId + "'", ex);
            AuthenticationServiceException e = new AuthenticationServiceException(ex.getMessage());
            publish(new AuthenticationFailureServiceExceptionEvent(req, e));
            throw e;
        }

        String upn = VmidentityUtils.getPrincipalUpn(userId);
        List<GrantedAuthority> authorities = null;
        try {
            authorities = VmidentityUtils.getUserAuthorities(this.idmClient, userId, tenant, systemDomain);
            authorities.addAll(defaultAuthorities);

            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Authorities for user '%s':", userId.getUPN()));

                for( GrantedAuthority ga : authorities ) {
                    logger.debug(ga.getAuthority());
                }
            }
        } catch (Exception ex) {
            logger.warn("Auth failed for user '" + req.getName() + "'.", ex);
            AuthenticationServiceException e = new AuthenticationServiceException(ex.getMessage());
            publish(new AuthenticationFailureServiceExceptionEvent(req, e));
            throw e;
        }

        UaaAuthentication success = new UaaAuthentication(
                new UaaPrincipal(
                        upn,
                        upn,
                        upn,
                        origin,
                        null,
                        tenant),
                authorities,
                (UaaAuthenticationDetails) req.getDetails());

        success.setAuthenticationMethods(Collections.singleton("pwd"));

        UaaUserPrototype proto =
            new UaaUserPrototype()
               .withId(upn) // todo: this should probably become objectId
               .withZoneId(tenant)
               .withUsername(upn)
               .withOrigin(origin)
               .withEmail(upn) // email is required; now idm it is optional //
               .withAuthorities(authorities);
        publish(new UserAuthenticationSuccessEvent(new UaaUser(proto), success));

        return success;
    }

    private void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }
}
