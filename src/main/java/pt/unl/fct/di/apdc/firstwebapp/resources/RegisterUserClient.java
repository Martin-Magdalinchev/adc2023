package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.gson.Gson;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Transaction;

import pt.unl.fct.di.apdc.firstwebapp.util.RegisterData;

@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RegisterUserClient {

	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

	private final Gson g = new Gson();

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	public RegisterUserClient() {
	} // Nothing to be done here

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doRegistrationV1(RegisterData data) {
		LOG.fine("Attempt to register user: " + data.username);

		// Checks input data
		if (!data.validRegistration()) {
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter").build();
		}
		// Creates an entity user from data. The key is the username
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = Entity.newBuilder(userKey).set("user_pwd", DigestUtils.sha512Hex(data.password))
				.set("user_creation_time", Timestamp.now()).build();
		datastore.put(user);
		LOG.info("User registered " + data.username);

		return Response.ok("{}").build();
	}

	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doRegistrationV2(RegisterData data) {
		LOG.fine("Attempt to register user: " + data.username);

		// Checks input data
		if (!data.validRegistration()) {
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter").build();
		}

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = datastore.get(userKey);

		if (user != null) {
			return Response.status(Status.BAD_REQUEST).entity("User already exists!").build();
		} else {
			user = Entity.newBuilder(userKey)
					.set("user_name", data.name)
					.set("user_pwd", DigestUtils.sha512Hex(data.password))
					.set("user_email", data.email)
					.set("user_creation_time", Timestamp.now())
					.build();
		}
		datastore.add(user);
		LOG.info("User registered " + data.username);

		return Response.ok("{}").build();
	}

	@POST
	@Path("/v3")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doRegistrationV4(RegisterData data) {

		LOG.fine("Attempt to register user: " + data.username);

		// Checks input data
		if (!data.validRegistration()) {
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter").build();
		}

		Transaction txn = datastore.newTransaction();
		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
			Entity user = txn.get(userKey);
			if (user != null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User already exists!").build();
			} else {
				user = Entity.newBuilder(userKey)
						.set("user_name", data.name)
						.set("user_pwd", DigestUtils.sha512Hex(data.password))
						.set("user_email", data.email)
						.set("user_creation_time", Timestamp.now())
						.build();
				txn.add(user);
				LOG.info("User registered " + data.username);
				txn.commit();
				return Response.ok("{}").build();
			}
		} finally {
			if (txn.isActive()) {
				txn.rollback();
			}
		}

	}
}
