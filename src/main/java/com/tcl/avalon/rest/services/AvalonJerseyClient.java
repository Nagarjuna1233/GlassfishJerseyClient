package com.tcl.avalon.rest.services;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.InvocationCallback;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.glassfish.jersey.apache.connector.ApacheClientProperties;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.backoff.ExponentialBackOffPolicy;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;

/**
 * 
 * @author Techouts-1194 Advance glass fish jersey rest client
 *
 */
public class AvalonJerseyClient {

	private static final Logger LOG = LoggerFactory.getLogger(AvalonJerseyClient.class);

	private String url = null;
	private Builder builder = null;
	private ClientConfig clientConfig;
	private Client client = null;
	private int connectRetry = 0;
	private Class<? extends Exception> retryExceptionType;
	private ExponentialBackOffPolicy retrybackOffPolicy;
	private RetryTemplate retryTemplate;

	public Class<? extends Exception> getRetryExceptionType() {
		return retryExceptionType;
	}

	public ExponentialBackOffPolicy getRetrybackOffPolicy() {
		return retrybackOffPolicy;
	}

	public ClientConfig getClientConfig() {
		return clientConfig;
	}

	public AvalonJerseyClient(AvaloneHttpBuilder builder) {
		this.url = builder.url;
		this.builder = builder.builder;
		this.clientConfig = builder.clientConfig;
		this.client = builder.client;
		this.connectRetry = builder.retryCount;
		this.retryExceptionType = builder.retryExceptionType;
		this.retrybackOffPolicy = builder.retrybackOffPolicy;
		this.retryTemplate = builder.retryTemplate;
	}

	public Response get() throws Exception {
		return this.syncMethod(AvalonClientConstants.GET, Response.class);
	}

	public <T> T get(Class<T> responseType) throws Exception {
		return this.syncMethod(AvalonClientConstants.GET, responseType);
	}

	public Response post() throws Exception {
		return syncMethod(AvalonClientConstants.POST,Response.class);
	}
	
	public <T> T post(Class<T> responseType) throws Exception {
		return syncMethod(AvalonClientConstants.POST,responseType);
	}
	
	public Response post(final Entity<?> entity) throws Exception {
		return syncMethod(AvalonClientConstants.POST, entity, Response.class);
	}
	
	

	public <T> T post(final Entity<?> entity, final Class<T> responseType) throws Exception {

		return syncMethod(AvalonClientConstants.POST, entity, responseType);
	}
	
	public Response postAsyn() throws Exception {
		return asyncMethod(AvalonClientConstants.POST,Response.class);
	}
	
	public <T> T postAsyn(Class<T> responseType) throws Exception {
		return asyncMethod(AvalonClientConstants.POST,responseType);
	}

	public Response postAsync(final Entity<?> entity) throws Exception {
		return asyncMethod(AvalonClientConstants.POST, entity, Response.class);
	}

	public <T> T postAsync(final Entity<?> entity, final Class<T> responseType) throws Exception {
		return asyncMethod(AvalonClientConstants.POST, responseType);
	}

	public Response getAsync() throws Exception {
		return asyncMethod(AvalonClientConstants.GET, Response.class);
	}

	public <T> T getAsync(Class<T> responseType) throws Exception {

		return asyncMethod(AvalonClientConstants.GET, responseType);
	}

	public <T> T postAsync(final Entity<?> entity, InvocationCallback<T> invocationCallback) throws Exception {
		return asyncMethod(AvalonClientConstants.POST, entity, invocationCallback);
	}

	public <T> T getAsync(InvocationCallback<T> invocationCallback) throws Exception {
		return asyncMethod(AvalonClientConstants.GET, invocationCallback);
	}

	public void closeConnection() {
		this.client.close();
	}

	public <T> T syncMethod(String name, final Class<T> responseType) throws Exception {
		T response = null;
		try {
			response = getBuilder().method(name, responseType);
		} catch (Exception exception) {
			RetryTemplate temp = this.retryTemplate;
			if (temp != null) {
				if (getRetryExceptionType().isInstance(getRootCause(exception))) {
					LOG.debug("Retry enabled for url {},count {}", this.url, this.connectRetry);
					response = temp.execute(new RetryCallback<T, Exception>() {
						@Override
						public T doWithRetry(RetryContext context) throws Exception {
							try {
								return getBuilder().method(name, responseType);

							} catch (Exception exception) {
								Throwable rootCause = getRootCause(exception);
								if (getRetryExceptionType().isInstance(rootCause)) {
									throw (Exception) rootCause;
								} else {
									throw exception;
								}
							}
						}
					});
				} else {
					throw exception;
				}
			} else {
				throw exception;
			}
		}
		return response;
	}

	public <T> T syncMethod(String name, final Entity<?> entity, final Class<T> responseType) throws Exception {
		T response = null;
		try {
			response = getBuilder().method(name, entity, responseType);
		} catch (Exception exception) {
			RetryTemplate temp = this.retryTemplate;
			if (temp != null) {
				if (getRetryExceptionType().isInstance(getRootCause(exception))) {
					LOG.debug("Retry enabled for url {},count {}", this.url, this.connectRetry);
					response = temp.execute(new RetryCallback<T, Exception>() {
						@Override
						public T doWithRetry(RetryContext context) throws Exception {
							try {

								return getBuilder().method(name, entity, responseType);

							} catch (Exception exception) {
								Throwable rootCause = getRootCause(exception);
								if (getRetryExceptionType().isInstance(rootCause)) {
									throw (Exception) rootCause;
								} else {
									throw exception;
								}
							}
						}
					});
				} else {
					throw exception;
				}
			} else {
				throw exception;
			}
		}
		return response;

	}

	public <T> T asyncMethod(String name, final Class<T> responseType) throws Exception {
		T response = null;
		try {
			response = getBuilder().async().method(name, responseType).get();
		} catch (Exception exception) {
			RetryTemplate temp = this.retryTemplate;
			if (temp != null) {
				if (getRetryExceptionType().isInstance(getRootCause(exception))) {
					LOG.debug("Retry enabled for url {},count {}", this.url, this.connectRetry);
					response = temp.execute(new RetryCallback<T, Exception>() {
						@Override
						public T doWithRetry(RetryContext context) throws Exception {
							try {

								return getBuilder().async().method(AvalonClientConstants.GET, responseType).get();

							} catch (Exception exception) {
								Throwable rootCause = getRootCause(exception);
								if (getRetryExceptionType().isInstance(rootCause)) {
									throw (Exception) rootCause;
								} else {
									throw exception;
								}
							}
						}
					});
				} else {
					throw exception;
				}
			} else {
				throw exception;
			}
		}
		return response;
	}

	public <T> T asyncMethod(String name, Entity<?> entity, InvocationCallback<T> invocationCallback) throws Exception {
		T response = null;
		try {
			response = getBuilder().async().method(name, entity, invocationCallback).get();
		} catch (Exception exception) {
			RetryTemplate temp = this.retryTemplate;
			if (temp != null) {
				if (getRetryExceptionType().isInstance(getRootCause(exception))) {
					LOG.debug("Retry enabled for url {},count {}", this.url, this.connectRetry);
					response = temp.execute(new RetryCallback<T, Exception>() {
						@Override
						public T doWithRetry(RetryContext context) throws Exception {
							try {

								return getBuilder().async().method(name, entity, invocationCallback).get();

							} catch (Exception exception) {
								Throwable rootCause = getRootCause(exception);
								if (getRetryExceptionType().isInstance(rootCause)) {
									throw (Exception) rootCause;
								} else {
									throw exception;
								}
							}
						}
					});
				} else {
					throw exception;
				}
			} else {
				throw exception;
			}
		}
		return response;
	}

	public <T> T asyncMethod(String name, InvocationCallback<T> invocationCallback) throws Exception {
		T response = null;
		try {
			response = getBuilder().async().method(name, invocationCallback).get();
		} catch (Exception exception) {
			RetryTemplate temp = this.retryTemplate;
			if (temp != null) {
				if (getRetryExceptionType().isInstance(getRootCause(exception))) {
					LOG.debug("Retry enabled for url {},count {}", this.url, this.connectRetry);
					response = temp.execute(new RetryCallback<T, Exception>() {
						@Override
						public T doWithRetry(RetryContext context) throws Exception {
							try {

								return getBuilder().async().method(name, invocationCallback).get();

							} catch (Exception exception) {
								Throwable rootCause = getRootCause(exception);
								if (getRetryExceptionType().isInstance(rootCause)) {
									throw (Exception) rootCause;
								} else {
									throw exception;
								}
							}
						}
					});
				} else {
					throw exception;
				}
			} else {
				throw exception;
			}
		}
		return response;
	}

	public <T> T asyncMethod(String name, final Entity<?> entity, final Class<T> responseType) throws Exception {

		T response = null;
		try {
			response = getBuilder().async().method(name, entity, responseType).get();
		} catch (Exception exception) {
			RetryTemplate temp = this.retryTemplate;
			if (temp != null) {
				if (getRetryExceptionType().isInstance(getRootCause(exception))) {
					LOG.debug("Retry enabled for url {},count {}", this.url, this.connectRetry);
					response = temp.execute(new RetryCallback<T, Exception>() {
						@Override
						public T doWithRetry(RetryContext context) throws Exception {
							try {

								return getBuilder().async().method(name, entity, responseType).get();

							} catch (Exception exception) {
								Throwable rootCause = getRootCause(exception);
								if (getRetryExceptionType().isInstance(rootCause)) {
									throw (Exception) rootCause;
								} else {
									throw exception;
								}
							}
						}
					});
				} else {
					throw exception;
				}
			} else {
				throw exception;
			}
		}
		return response;
	}

	protected Throwable getRootCause(final Throwable throwable) {
		if (throwable.getCause() != null) {
			return getRootCause(throwable.getCause());
		}
		return throwable;
	}

	public Builder getBuilder() {
		return builder;
	}

	public static class AvaloneHttpBuilder {

		private ClientConfig clientConfig = null;
		private Client client = null;
		private String acceptType = MediaType.APPLICATION_JSON;
		private Map<String, String> headers = new LinkedHashMap<String, String>();
		private String url = null;
		private Builder builder;
		private int retryCount = 0;
		private Class<? extends Exception> retryExceptionType;
		private ExponentialBackOffPolicy retrybackOffPolicy;
		private RetryTemplate retryTemplate;

		public AvaloneHttpBuilder setRetry(int count, Class<? extends Exception> retryExceptionType,
				ExponentialBackOffPolicy retrybackOffPolicy) {
			this.retryCount = count;
			this.retryExceptionType = retryExceptionType;
			this.retrybackOffPolicy = retrybackOffPolicy;
			return this;
		}

		public AvaloneHttpBuilder setRetry(int count, Class<? extends Exception> retryExceptionType) {
			this.retryCount = count;
			this.retryExceptionType = retryExceptionType;
			return this;
		}

		public AvaloneHttpBuilder(String url) {
			this.client = ClientBuilder.newBuilder().register(JacksonFeature.class).build();
			this.url = url;
		}

		public AvaloneHttpBuilder(String url, ClientConfig clientConfig) {
			this.url = url;
			this.clientConfig = clientConfig;
			this.client = ClientBuilder.newBuilder().register(JacksonFeature.class).register(clientConfig).build();
		}

		public AvaloneHttpBuilder setAccept(String acceptType) {
			this.acceptType = acceptType;
			return this;
		}

		public AvaloneHttpBuilder setBasicAuthentication(String userName, String password) {
			HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(userName, password);
			this.client.register(feature);
			return this;
		}

		public AvaloneHttpBuilder setHeader(String key, String value) {
			this.headers.put(key, value);
			return this;
		}

		public void setPoolingConnectionManager(PoolingHttpClientConnectionManager poolingClientConnectionManager) {
			if (this.clientConfig == null) {
				this.clientConfig = new ClientConfig();
				this.clientConfig.property(ApacheClientProperties.CONNECTION_MANAGER, poolingClientConnectionManager);
				this.client.register(this.clientConfig);
			} else {
				this.clientConfig.property(ApacheClientProperties.CONNECTION_MANAGER, poolingClientConnectionManager);
				this.client.register(this.clientConfig);
			}
		}

		public <T> AvaloneHttpBuilder setLogger(Class<T> responseType) {
			this.client.register(responseType);
			return this;
		}

		/**
		 * Create and configure a retry template if the consumer 'maxAttempts'
		 * property is set.
		 * 
		 * @param properties
		 *            The properties.
		 * @return The retry template, or null if retry is not enabled.
		 */
		protected RetryTemplate getRetryTemplateIfRetryEnabled(int retryCount,
				final Class<? extends Throwable> retryException, ExponentialBackOffPolicy backOffPolicy) {
			if (retryCount >= 1 && retryException != null) {
				RetryTemplate template = new RetryTemplate();
				SimpleRetryPolicy retryPolicy = new SimpleRetryPolicy(retryCount,
						Collections.<Class<? extends Throwable>, Boolean>singletonMap(retryException, true));
				template.setRetryPolicy(retryPolicy);
				template.setBackOffPolicy(backOffPolicy);
				return template;
			}
			return null;
		}

		public AvalonJerseyClient build() {
			this.builder = client.target(this.url).request().accept(this.acceptType);
			for (Entry<String, String> headerSet : this.headers.entrySet()) {
				this.builder = builder.header(headerSet.getKey(), headerSet.getValue());
			}
			this.retryTemplate = getRetryTemplateIfRetryEnabled(this.retryCount, this.retryExceptionType,
					this.retrybackOffPolicy);
			return new AvalonJerseyClient(this);
		}
	}

	public static class AvaloneHttpsBuilder extends AvaloneHttpBuilder {

		private String keyStorePath;
		private String keyStoreType;
		private String keyStorePassword;

		private String sslProtocalType = "TLSv1.1";
		private String keyManagerAlgorithm = "X509";

		public AvaloneHttpsBuilder(String url) throws KeyManagementException, NoSuchAlgorithmException {
			super(url);
			super.client = getHttpsClient().build();
			super.url = url;
		}
		
		public AvaloneHttpsBuilder(String url,String sslProtocalType) throws KeyManagementException, NoSuchAlgorithmException {
			super(url);
			this.sslProtocalType=sslProtocalType;
			super.client = getHttpsClient().build();
			super.url = url;
		}

		public AvaloneHttpsBuilder(String url, String keyStorePath, String keyStoreType, String keyStorePassword,
				String sslProtocalType, String keyManagerAlgorithm)
				throws KeyManagementException, NoSuchAlgorithmException, UnrecoverableKeyException,
				CertificateException, FileNotFoundException, KeyStoreException, IOException {
			super(url);
			this.keyStorePath = keyStorePath;
			this.keyStoreType = keyStoreType;
			this.keyStorePassword = keyStorePassword;
			this.sslProtocalType = sslProtocalType;
			this.keyManagerAlgorithm = keyManagerAlgorithm;
			super.client = getTrustedHttpsClient().build();
			super.url = url;
		}

		public AvaloneHttpsBuilder(String url, ClientConfig clientConfig, String keyStorePath, String keyStoreType,
				String keyStorePassword, String sslProtocalType, String keyManagerAlgorithm)
				throws KeyManagementException, NoSuchAlgorithmException {
			super(url, clientConfig);
			this.keyStorePath = keyStorePath;
			this.keyStoreType = keyStoreType;
			this.keyStorePassword = keyStorePassword;
			this.sslProtocalType = sslProtocalType;
			this.keyManagerAlgorithm = keyManagerAlgorithm;
			super.client = getHttpsClient().withConfig(clientConfig).build();
			super.url = url;
		}

		public AvaloneHttpsBuilder(String url, String keyStorePath, String keyStoreType, String keyStorePassword)
				throws KeyManagementException, NoSuchAlgorithmException, UnrecoverableKeyException,
				CertificateException, FileNotFoundException, KeyStoreException, IOException {
			super(url);
			this.keyStorePath = keyStorePath;
			this.keyStoreType = keyStoreType;
			this.keyStorePassword = keyStorePassword;
			super.client = getTrustedHttpsClient().build();
			super.url = url;
		}

		public AvaloneHttpsBuilder(String url, ClientConfig clientConfig, String keyStorePath, String keyStoreType,
				String keyStorePassword) throws KeyManagementException, NoSuchAlgorithmException {
			super(url, clientConfig);
			this.keyStorePath = keyStorePath;
			this.keyStoreType = keyStoreType;
			this.keyStorePassword = keyStorePassword;
			super.client = getHttpsClient().withConfig(clientConfig).build();
			super.url = url;
		}

		public AvaloneHttpsBuilder(String url, ClientConfig clientConfig)
				throws KeyManagementException, NoSuchAlgorithmException {
			super(url, clientConfig);
			super.client = getHttpsClient().withConfig(clientConfig).build();
			super.url = url;
		}

		protected ClientBuilder getHttpsClient() throws KeyManagementException, NoSuchAlgorithmException {
			SSLContext sc = SSLContext.getInstance(this.sslProtocalType);// Java8
			System.setProperty("https.protocols", this.sslProtocalType);// Java8
			TrustManager[] trustAllCerts = { new AvalonDummyInsecureTrustManager() };
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HostnameVerifier allHostsValid = new AvalonDummyInsecureHostnameVerifier();
			return ClientBuilder.newBuilder().sslContext(sc).hostnameVerifier(allHostsValid);
		}

		public void setSslProtocalType(String sslProtocalType) {
			this.sslProtocalType = sslProtocalType;
		}

		protected ClientBuilder getTrustedHttpsClient() throws KeyManagementException, NoSuchAlgorithmException,
				CertificateException, FileNotFoundException, IOException, KeyStoreException, UnrecoverableKeyException {

			SSLContext sc = SSLContext.getInstance(this.sslProtocalType);// Java8
			System.setProperty("https.protocols", this.sslProtocalType);// Java8

			KeyStore cks = KeyStore.getInstance(this.keyStoreType);
			cks.load(new FileInputStream(this.keyStorePath), this.keyStorePassword.toCharArray());
			// .loadTrustMaterial(tks, new TrustSelfSignedStrategy()) // use it
			// to customize
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(this.keyManagerAlgorithm);
			keyManagerFactory.init(cks, this.keyStorePassword.toCharArray());

			final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(cks);

			sc.init(keyManagerFactory.getKeyManagers(), tmf.getTrustManagers(), null);
			HostnameVerifier allHostsValid = new AvalonDummyInsecureHostnameVerifier();

			return ClientBuilder.newBuilder().sslContext(sc).hostnameVerifier(allHostsValid);
		}

	}
}
