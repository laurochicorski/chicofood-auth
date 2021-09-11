package com.chicorski.chicofoodauth.core;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

public class JwtCustomClaimsTokenExchancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        if (authentication.getPrincipal() instanceof AuthUser) {
            var authUser = (AuthUser) authentication.getPrincipal();

            var info = new HashMap<String, Object>();

            info.put("nome_completo", authUser.getFullName());
            info.put("id", authUser.getUserId());

            var oAuth2AcessToken = (DefaultOAuth2AccessToken) accessToken;

            oAuth2AcessToken.setAdditionalInformation(info);
        }

        return accessToken;
    }
}