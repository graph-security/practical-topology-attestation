package uk.ac.ncl.cascade.zkpgs.message;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.IOException;
import java.util.logging.Logger;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_OK;

/**
 * Message handler for JSON messages that are sent using HttpMessageGateway
 */
public class GSMessageHandler implements HttpHandler {
	//	public static final int HTTP_OK = HttpURLConnection.HTTP_OK;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private HttpExchange exc;

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		this.exc = exchange;
		String requestMethod = exchange.getRequestMethod();
		gslog.info(requestMethod + " /");
		gslog.info("uri : " + exchange.getRequestURI());
		gslog.info("path : " + exchange.getHttpContext().getPath());
		gslog.info("server : " + exchange.getHttpContext().getServer());
		if (requestMethod.equalsIgnoreCase("POST")) {

			if (String.valueOf(exchange.getRequestURI()).equals(exchange.getHttpContext().getPath())) {

				gslog.info(this.getClass().getName() + " POST");

				JsonReader reader = Json.createReader(exchange.getRequestBody());
				JsonObject jsonObject = reader.readObject();
				gslog.info("json object: " + jsonObject.toString());
				//send Http response code 200
				exchange.sendResponseHeaders(HTTP_OK, -1);
//				OutputStream os = exchange.getResponseBody();
//				os.close();
			} else {
				//send Http response code 400
				exchange.sendResponseHeaders(HTTP_BAD_REQUEST, -1);
			}
		}

	}

}
