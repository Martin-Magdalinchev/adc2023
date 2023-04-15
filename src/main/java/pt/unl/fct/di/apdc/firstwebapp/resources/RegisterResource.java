package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;

import com.google.gson.Gson;
import com.google.cloud.Timestamp;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.RegisterData;

@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RegisterResource {

	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

	private final Gson g = new Gson();

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	public RegisterResource() {
	} // Nothing to be done here

	@POST
	@Path("/v3")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doRegistrationV4(RegisterData data) {


		// Checks input data
		if (!data.validRegistration()) {
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter").build();
		}

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username))
				.setKind("User Token").newKey(data.username);
		Transaction txn = datastore.newTransaction();


		try {
			Entity user = txn.get(userKey);
			if (user != null) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User already exists!").build();
			} else {
				user = Entity.newBuilder(userKey)
						.set("user_name", data.name)
						.set("user_pwd", DigestUtils.sha512Hex(data.password))
						.set("user_email", data.email)
						.set("user_typeOfAccount", data.typeOfAccount)
						.set("user_phone", "")
						.set("user_mobile_phone", "")
						.set("user_occupation", "")
						.set("user_work_place", "")
						.set("user_address", "")
						.set("user_nif", "")
						.set("user_role", "USER")
						.set("user_state","Inativo" )
						.set("user_creation_time", Timestamp.now())
						.build();

				AuthToken token = new AuthToken(data.username, user.getString("user_role"));
				Entity user_token = Entity.newBuilder(tokenKey)
						.set("user_token_ID", token.tokenID)
						.set("user_token_role", token.role)
						.set("user_token_creation_data", token.creationData)
						.set("user_token_expiration_data", token.expirationData)
						.build();

				txn.add(user, user_token);
				LOG.info("User registered " + data.username);
				txn.commit();
				return Response.ok(g.toJson(token)).build();
			}
		} finally {
			if (txn.isActive()) {
				txn.rollback();
			}
		}

	}
}
