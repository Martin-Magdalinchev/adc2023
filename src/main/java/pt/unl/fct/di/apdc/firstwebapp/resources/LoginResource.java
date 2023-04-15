package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import com.google.gson.Gson;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

	private final Gson g = new Gson();

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	public LoginResource() {
	} // Nothing to be done here

	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
	public Response doLogin2(LoginData data, @Context HttpServletRequest request, @Context HttpHeaders headers) {

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Key ctrsKey = datastore.newKeyFactory()
				.addAncestor(PathElement.of("User", data.username))
				.setKind("User Stats").newKey("counters");
		// Generate automatically a key
		Key logKey = datastore.allocateId(datastore.newKeyFactory()
				.addAncestor(PathElement.of("User", data.username))
				.setKind("UserLog").newKey());
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username))
				.setKind("User Token").newKey(data.username);
		Transaction txn = datastore.newTransaction();
		try {
			Entity user = txn.get(userKey);
			if( user == null ) {
				//Username does not exist
				txn.rollback();
				LOG.warning("Failed login attempt for username: " + data.username);
				return Response.status(Status.NOT_FOUND).build();
			}
			// We get the user stats from the storage
			Entity stats = txn.get(ctrsKey);
			if( stats == null ) {
				stats = Entity.newBuilder(ctrsKey)
						.set("user_stats_logins", 0L)
						.set("user_stats_failed", 0L)
						.set("user_first_login", Timestamp.now())
						.set("user_last_login", Timestamp.now())
						.build();
			}
			String hashedPWD = user.getString("user_pwd");
			if(hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				if(user.getString("user_state").equals("Inativo")){
					txn.rollback();
					LOG.warning("Account disabled");
					return Response.status(Status.METHOD_NOT_ALLOWED).build();
				}
				// Password is correct
				// Construct the logs
				AuthToken token = new AuthToken(data.username, user.getString("user_role"));

				Entity user_token = Entity.newBuilder(tokenKey)
						.set("user_token_ID", token.tokenID)
						.set("user_token_role", token.role)
						.set("user_token_creation_data", token.creationData)
						.set("user_token_expiration_data", token.expirationData)
						.build();

				Entity log = Entity.newBuilder(logKey)
						.set("user_login_ip", request.getRemoteAddr())
						.set("user_logins_host", request.getRemoteHost())
						.set("user_login_latlon",
								StringValue.newBuilder(headers.getHeaderString("X-AppEngine-CityLatLong"))
										.setExcludeFromIndexes(true).build())
						.set("user_login_city", headers.getHeaderString("X-AppEngine-City"))
						.set("user_login_country", headers.getHeaderString("X-AppEngine-Country"))
						.set("user_login_time", Timestamp.now())
						.build();

				// Get the user statistics and updates it
				// Copying information every time a user logins maybe is not a good solution (why?)
				Entity ustats = Entity.newBuilder(ctrsKey)
						.set("user_stats_logins", 1L + stats.getLong("user_stats_logins"))
						.set("user_stats_failed", stats.getLong("user_stats_failed")) // ou 0
						.set("user_first_login", stats.getTimestamp("user_first_login"))
						.set("user_last_login", Timestamp.now())
						.build();

				// Batch operations
				txn.put(log, ustats, user_token);
				txn.commit();

				// Return token

				LOG.info("User '" + data.username + "' logged in sucessfully.");
				return Response.ok(g.toJson(token)).build();
			} else {
				// Incorrect password
				// Copying here is even worse. Propose a better solution!
				Entity ustats = Entity.newBuilder(ctrsKey)
						.set("user_stats_logins", stats.getLong("user_stats_logins"))
						.set("user_stats_failed", 1L + stats.getLong("user_stats_failed"))
						.set("user_first_login", stats.getTimestamp("user_first_login"))
						.set("user_last_login", stats.getTimestamp("user_last_login"))
						.set("user_last_attempt", Timestamp.now())
						.build();
				txn.put(ustats);
				txn.commit();
				LOG.warning("Wrong password for username: " + data.username);
				return Response.status(Status.FORBIDDEN).build();
			}
		} catch (Exception e) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@POST
	@Path("/user")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
	public Response checkUsernameAvailableV2(LoginData data) {

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = datastore.get(userKey);

		if (user != null && user.getString("user_pwd").equals(DigestUtils.sha512Hex(data.password))) {
			// Get the date of yesterday
			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.DATE, -1);
			Timestamp yesterday = Timestamp.of(cal.getTime());

			Query<Entity> query = Query.newEntityQueryBuilder()
					.setKind("UserLog")
					.setFilter(
							StructuredQuery.CompositeFilter.and(
									StructuredQuery.PropertyFilter.hasAncestor(
											datastore.newKeyFactory().setKind("User").newKey(data.username)
									), StructuredQuery.PropertyFilter.ge("user_login_time", yesterday)
							)
					).build();

			QueryResults<Entity> logs = datastore.run(query);
			List<Date> loginDates = new ArrayList<>();
			logs.forEachRemaining(userlog -> {
				loginDates.add(userlog.getTimestamp("user_login_time").toDate());
			});
			return Response.ok(g.toJson(loginDates)).build();
		} else {
			LOG.warning("Wrong password for username: " + data.username);
			return Response.status(Status.FORBIDDEN).build();
		}

	}
//
//	@GET
//	@Path("/{username}")
//	public Response checkUsernameAvailable(@PathParam("username") String username) {
//		if (username.equals("maptih")) {
//			return Response.ok().entity(g.toJson(false)).build();
//		} else {
//			return Response.ok().entity(g.toJson(true)).build();
//		}
//	}

}
