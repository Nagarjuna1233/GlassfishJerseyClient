package com.tcl.avalon.rest.filters;

import java.io.IOException;
import java.net.URI;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.core.MultivaluedMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tcl.avalon.rest.services.AvalonJerseyClient;

/** 
 * 
 * @author Techouts-1194
 * Logging filter for rest client {@link AvalonJerseyClient}
 */
public class AvalonLoggerClientFilter implements ClientResponseFilter, ClientRequestFilter {

	private static final Logger LOG = LoggerFactory.getLogger(AvalonLoggerClientFilter.class);

	@Override
	public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
		if (LOG.isInfoEnabled()) {
			LOG.info("### Client response info ###");
			responseLog(requestContext.getUri(), requestContext.getHeaders(), responseContext.getStatus());
		}
	}

	@Override
	public void filter(ClientRequestContext requestContext) throws IOException {
		if (LOG.isInfoEnabled()) {
			LOG.info("### Client request info ### ");
			requestLog(requestContext.getUri(), requestContext.getHeaders());
		}

	}

	private void requestLog(URI uri, MultivaluedMap<String, ?> headers) {
		LOG.info("Request URI: {}", uri.getPath());
		LOG.info("Headers: ");
		headers.entrySet().forEach(h -> LOG.info(h.getKey() + ": " + h.getValue()));
	}

	private void responseLog(URI uri, MultivaluedMap<String, ?> headers, int code) {
		LOG.info("Request URI: {}", uri.getPath());
		LOG.info("Response status code: {}", code);
		LOG.info("Headers: ");
		headers.entrySet().forEach(h -> LOG.info(h.getKey() + ": " + h.getValue()));
	}

}
