package com.tcl.avalon.rest.dtos;

/** 
 * 
 * @author Techouts-1194
 * Access token managed dto
 */
public class AvalonAccessTokenManager {

	
	private String accessToken;
	private String tokenType;
	private String refreshToken;
	private int expiresInSeconds;
	private String scope;
	
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public String getTokenType() {
		return tokenType;
	}
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public int getExpiresInSeconds() {
		return expiresInSeconds;
	}
	public void setExpiresInSeconds(int expiresInSeconds) {
		this.expiresInSeconds = expiresInSeconds;
	}
	
}
