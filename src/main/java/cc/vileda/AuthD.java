package cc.vileda;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import org.apache.commons.lang3.StringUtils;


public class AuthD {

	private final Vertx vertx;
	private final String remoteHost;
	private final String keystoreSecret;

	public static void main(String[] args) throws Exception {
		Vertx vertx = Vertx.vertx();

		if (args.length != 2) {
			System.err.println("<remote_host:port> <keystore_secret>");
			return;
		}

		final String remoteHost = args[0];
		final String keystoreSecret = args[1];

		new AuthD(vertx, remoteHost, keystoreSecret).run();
	}

	public AuthD(Vertx vertx, String remoteHost, String keystoreSecret) {

		this.vertx = vertx;
		this.remoteHost = remoteHost;
		this.keystoreSecret = keystoreSecret;
	}

	private void run() {
		HttpServer server = vertx.createHttpServer();

		Router router = createRouter();

		JWTAuth provider = getJwtAuth();

		createRoutes(router, provider);

		server.requestHandler(router::accept).listen(8080);
	}

	private void createRoutes(final Router router, final JWTAuth provider) {
		router.postWithRegex("^/login$").handler(getLoginHandler(provider));
		router.route("/*").handler(getProxyHandler(provider));
	}

	private Router createRouter() {
		Router router = Router.router(vertx);
		router.route().handler(BodyHandler.create());
		return router;
	}

	private Handler<RoutingContext> getProxyHandler(final JWTAuth provider) {
		return routingContext -> {
			final HttpServerResponse response = routingContext.response();
			final HttpServerRequest request = routingContext.request();

			String jwtToken = extractJwtToken(request);

			if (jwtToken == null) {
				response.setStatusCode(412).end("Authorization header not set or incorrect");
			} else {
				proxyAuthenticatedRequest(provider, response, request, jwtToken);
			}
		};
	}

	private void proxyAuthenticatedRequest(final JWTAuth provider, final HttpServerResponse response,
																				 final HttpServerRequest request, final String jwtToken) {
		final JsonObject jsonObject = new JsonObject().put("jwt", jwtToken);
		if(response.headWritten()) return;
		provider.authenticate(jsonObject, userAsyncResult -> {
			if (userAsyncResult.succeeded()) {
				System.out.println(userAsyncResult.result().principal().getString("sub"));
				proxyRequest(response, request);
			}
			else response.setStatusCode(401).end();
		});
	}

	private void proxyRequest(HttpServerResponse response, HttpServerRequest request) {
		final String uri = request.uri();
		final HttpClient httpClient = vertx.createHttpClient();
		request.handler(proxyResponseHandler(response, request, uri, httpClient));
	}

	private Handler<Buffer> proxyResponseHandler(final HttpServerResponse response, final HttpServerRequest request,
																							 final String uri, final HttpClient httpClient) {
		return buffer -> httpClient.requestAbs(request.method(),
				String.format("http://%s%s", remoteHost, uri),
				httpClientResponse -> {
					response.headers().setAll(httpClientResponse.headers());
					httpClientResponse.bodyHandler(response::end);
				}).end(buffer);
	}

	private String extractJwtToken(final HttpServerRequest request) {
		final String authorizationHeader = request.getHeader("Authorization");
		String[] authorizations = new String[0];
		if (StringUtils.isNotEmpty(authorizationHeader)) authorizations = authorizationHeader.split(" ");
		if (authorizations.length != 2) return null;
		return authorizations[1];
	}

	private Handler<RoutingContext> getLoginHandler(final JWTAuth provider) {
		return routingContext -> {
			final HttpServerResponse response = routingContext.response();
			final String username = routingContext.request().getFormAttribute("username");
			final String password = routingContext.request().getFormAttribute("password");

			response.putHeader("content-type", "text/plain");
			authenticate(provider, response, username, password);
		};
	}

	private void authenticate(final JWTAuth provider, final HttpServerResponse response,
														final String username, final String password) {
		if ("test".equals(username) && "test".equals(password)) {
			final String token = provider.generateToken(new JsonObject().put("sub", username), new JWTOptions());
			response.setStatusCode(200).end(token);
		} else {
			response.setStatusCode(401).end();
		}
	}

	private JWTAuth getJwtAuth() {
		final JsonObject config = new JsonObject().put("keyStore", new JsonObject()
				.put("path", "keystore.jceks")
				.put("type", "jceks")
				.put("password", keystoreSecret));

		return JWTAuth.create(vertx, config);
	}
}