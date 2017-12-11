package com.tcl.avalon.rest.services;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/** 
 * 
 * @author Techouts-1194
 * Dummy class for skipping SSL connection {@link AvalonJerseyClient}
 */
public class AvalonDummyInsecureHostnameVerifier implements HostnameVerifier 
{
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}