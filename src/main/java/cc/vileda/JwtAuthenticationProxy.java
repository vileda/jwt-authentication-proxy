package cc.vileda;

import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.*;
import io.vertx.ext.web.sstore.LocalSessionStore;
import org.apache.commons.lang3.StringUtils;


class JwtAuthenticationProxy {

	private static final String USERNAME_HEADER = "X-Username";
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
		final JWTAuth authProvider = getJwtAuth();

		Router router = Router.router(vertx);

		router.route().handler(BodyHandler.create());
		router.routeWithRegex("^((?!/login).)*$").handler(JWTAuthHandler.create(authProvider));

		router.route("/login").handler(routingContext -> {
			final HttpServerRequest request = routingContext.request();
			final HttpServerResponse response = routingContext.response();
			final String username = request.getFormAttribute("username");
			final String password = request.getFormAttribute("password");

			if ("test".equals(username) && "test".equals(password)) {
				final String token = authProvider.generateToken(new JsonObject().put("username", username), new JWTOptions());
				response.setStatusCode(200).end(token);
			} else {
				response.setStatusCode(401).end();
			}
		});

		router.route("/*").handler(routingContext -> {
			final HttpServerRequest request = routingContext.request();
			final HttpServerResponse response = routingContext.response();
			final String username = routingContext.user().principal().getString("username");
			final Buffer body = routingContext.getBody();
			proxyRequestToRemoteHost(response, request, body, username);
		});

		server.requestHandler(router::accept).listen(Integer.parseInt(listenPort));
	}

	private JWTAuth getJwtAuth() {
		final JsonObject config = new JsonObject().put("keyStore", new JsonObject()
				.put("path", "keystore.jceks")
				.put("type", "jceks")
				.put("password", keystoreSecret));

		return JWTAuth.create(vertx, config);
	}

	private void proxyRequestToRemoteHost(final HttpServerResponse response, final HttpServerRequest request,
																				final Buffer buffer, final String username) {
		final HttpClient httpClient = vertx.createHttpClient();
		final HttpMethod method = request.method();
		final String uri = request.uri();

		final HttpClientRequest httpClientRequest = httpClient.requestAbs(method, String.format("http://%s%s", remoteHost, uri),
				httpClientResponse -> {
					response.headers().setAll(httpClientResponse.headers());
					httpClientResponse.bodyHandler(response::end);
				});

		final MultiMap clientRequestHeaders = httpClientRequest.headers();
		final String originalHost = clientRequestHeaders.get("Host");
		clientRequestHeaders.addAll(request.headers());
		clientRequestHeaders.set(USERNAME_HEADER, username);

		if(originalHost != null) {
			clientRequestHeaders.set("Host", originalHost);
		}

		httpClientRequest.end(buffer);
	}
}