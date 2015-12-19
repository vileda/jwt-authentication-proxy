package cc.vileda;

import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.*;
import io.vertx.ext.web.sstore.LocalSessionStore;
import io.vertx.ext.web.sstore.SessionStore;
import org.apache.commons.lang3.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.TemporalField;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static io.vertx.core.http.HttpHeaders.SET_COOKIE;


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

	private JwtAuthenticationProxy(final Vertx vertx, String listenPort, final String remoteHost, final String keystoreSecret) {
		this.vertx = vertx;
		this.listenPort = listenPort;
		this.remoteHost = remoteHost;
		this.keystoreSecret = keystoreSecret;
	}

	private void run() {
		final HttpServer server = vertx.createHttpServer();
		final JWTAuth authProvider = getJwtAuth();

		final Router router = Router.router(vertx);

		router.route().handler(BodyHandler.create());
		router.route().handler(CorsHandler.create("http://localhost:3000").allowCredentials(true));
		router.route().handler(CookieHandler.create());

		router.route("/login").handler(loginHandler(authProvider));

		router.routeWithRegex("^((?!/login).)*$").handler(routingContext -> {
			routingContext.cookies().stream()
					.filter(cookie1 -> "auth".equals(cookie1.getName()))
					.findFirst().ifPresent(cookie2 -> {
						if ("auth".equals(cookie2.getName()) && StringUtils.isNotBlank(cookie2.getValue())) {
							routingContext.request().headers()
									.add("Authorization", "Bearer " + cookie2.getValue());
						}
					});
			JWTAuthHandler.create(authProvider).handle(routingContext);
		});

		router.route("/logout").handler(routingContext -> {
			Cookie cookie = Cookie.cookie("auth", "");
			cookie.setMaxAge(TimeUnit.DAYS.toSeconds(-1));
			routingContext.addCookie(cookie);
			routingContext.response().end("Bye!");
		});

		router.route("/*").handler(proxyHandler());

		server.requestHandler(router::accept).listen(Integer.parseInt(listenPort));
	}

	private Handler<RoutingContext> proxyHandler() {
		return routingContext -> {
			final HttpServerRequest request = routingContext.request();
			final HttpServerResponse response = routingContext.response();
			final String username = routingContext.user().principal().getString("username");
			final Buffer body = routingContext.getBody();
			proxyRequestToRemoteHost(response, request, body, username);
		};
	}

	private Handler<RoutingContext> loginHandler(final JWTAuth authProvider) {
		return routingContext -> {
			final HttpServerRequest request = routingContext.request();
			final HttpServerResponse response = routingContext.response();
			final String username = request.getFormAttribute("username");
			final String password = request.getFormAttribute("password");

			if ("test".equals(username) && "test".equals(password)) {
				final String token = authProvider.generateToken(new JsonObject().put("username", username), new JWTOptions());
				Cookie cookie = Cookie.cookie("auth", token);
				cookie.setMaxAge(TimeUnit.HOURS.toSeconds(12));
				cookie.setHttpOnly(true);
				routingContext.addCookie(cookie);
				response.setStatusCode(200).end(token);
			} else {
				response.setStatusCode(401).end();
			}
		};
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
					final MultiMap headers = httpClientResponse.headers();
					headers.remove("Access-Control-Allow-Origin");
					response.headers().addAll(headers);
					httpClientResponse.bodyHandler(response::end);
				});

		final MultiMap clientRequestHeaders = httpClientRequest.headers();
		final String originalHost = clientRequestHeaders.get("Host");
		clientRequestHeaders.addAll(request.headers());
		clientRequestHeaders.set(USERNAME_HEADER, username);

		if (originalHost != null) {
			clientRequestHeaders.set("Host", originalHost);
		}

		httpClientRequest.end(buffer);
	}
}