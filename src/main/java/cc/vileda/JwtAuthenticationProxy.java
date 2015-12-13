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


class JwtAuthenticationProxy {

	private final Vertx vertx;
	private final String listenPort;
	private final String remoteHost;
	private final String keystoreSecret;

	public static void main(String[] args) throws Exception {
		final Vertx vertx = Vertx.vertx();

		if (args.length != 3) {
			System.err.println("<listen_port> <remote_host:port> <keystore_secret>");
			return;
		}

		final String listenPort = args[0];
		final String remoteHost = args[1];
		final String keystoreSecret = args[2];

		new JwtAuthenticationProxy(vertx, listenPort, remoteHost, keystoreSecret).run();
	}

	private JwtAuthenticationProxy(final Vertx vertx, String listenPort, final String remoteHost, final String keystoreSecret)
	{
		this.vertx = vertx;
		this.listenPort = listenPort;
		this.remoteHost = remoteHost;
		this.keystoreSecret = keystoreSecret;
	}

	private void run() {
		final HttpServer server = vertx.createHttpServer();

		final Router router = createRouter();
		final Router loginRouter = createRouter();

		final JWTAuth authProvider = getJwtAuth();

		loginRouter.route().handler(BodyHandler.create());
		loginRouter.route().handler(getLoginHandler(authProvider));

		router.mountSubRouter("/login", loginRouter);

		router.route("/*").handler(handleSecuredRoutes(authProvider));

		server.requestHandler(router::accept).listen(Integer.parseInt(listenPort));
	}

	private Handler<RoutingContext> handleSecuredRoutes(final JWTAuth authProvider) {
		return routingContext -> {
			final HttpServerResponse response = routingContext.response();
			final HttpServerRequest request = routingContext.request();

			request.bodyHandler(handlerProxyRequest(authProvider, response, request));
		};
	}

	private Handler<Buffer> handlerProxyRequest(final JWTAuth authProvider,
																							final HttpServerResponse response, final HttpServerRequest request) {
		return buffer -> {
			final String authorizationHeader = request.getHeader("Authorization");
			final HttpMethod method = request.method();
			final String uri = request.uri();

			final String jwtToken = extractJwtToken(authorizationHeader);

			if (jwtToken == null) {
				response.setStatusCode(412).end("Authorization header not set or incorrect");
			} else {
				final JsonObject jsonObject = new JsonObject().put("jwt", jwtToken);
				authProvider.authenticate(jsonObject, userAsyncResult -> {
					if (userAsyncResult.succeeded()) {
						final String username = userAsyncResult.result().principal().getString("username");
						proxyRequestToRemoteHost(response, buffer, method, uri, username);
					} else {
						response.setStatusCode(401).end();
					}
				});
			}
		};
	}

	private void proxyRequestToRemoteHost(final HttpServerResponse response, final Buffer buffer,
																				final HttpMethod method, final String uri, final String username) {
		final HttpClient httpClient = vertx.createHttpClient();
		httpClient.requestAbs(method, String.format("http://%s%s", remoteHost, uri),
				httpClientResponse -> {
					response.headers().setAll(httpClientResponse.headers());
					httpClientResponse.bodyHandler(response::end);
				}).putHeader("username", username).end(buffer);
	}

	private Router createRouter() {
		return Router.router(vertx);
	}

	private JWTAuth getJwtAuth() {
		final JsonObject config = new JsonObject().put("keyStore", new JsonObject()
				.put("path", "keystore.jceks")
				.put("type", "jceks")
				.put("password", keystoreSecret));

		return JWTAuth.create(vertx, config);
	}

	private Handler<RoutingContext> getLoginHandler(final JWTAuth provider) {
		return routingContext -> {
			final HttpServerResponse response = routingContext.response();
			final HttpServerRequest request = routingContext.request();
			final String username = request.getFormAttribute("username");
			final String password = request.getFormAttribute("password");

			response.putHeader("content-type", "text/plain");
			authenticate(provider, response, username, password);
		};
	}

	private void authenticate(final JWTAuth provider, final HttpServerResponse response,
														final String username, final String password) {
		if ("test".equals(username) && "test".equals(password)) {
			final String token = provider.generateToken(new JsonObject().put("username", username), new JWTOptions());
			response.setStatusCode(200).end(token);
		} else {
			response.setStatusCode(401).end();
		}
	}

	private String extractJwtToken(final String authorizationHeader) {
		String[] authorizations = new String[0];
		if (StringUtils.isNotEmpty(authorizationHeader)) authorizations = authorizationHeader.split(" ");
		if (authorizations.length != 2) return null;
		return authorizations[1];
	}
}