package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;

import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.ChangePwdData;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;

@Path("/change")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangePwdResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public ChangePwdResource() {
    } // Nothing to be done here

    @POST
    @Path("/pwd")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePassword(ChangePwdData data, @Context HttpHeaders headers) {

        String authTokenHeader = headers.getHeaderString("Authorization");
        String authToken = authTokenHeader.substring("Bearer".length()).trim();
        AuthToken token = g.fromJson(authToken, AuthToken.class);

        Transaction txn = datastore.newTransaction();
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(token.username);
        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", token.username))
                .setKind("User Token").newKey(token.username);

        try {
            Entity user = txn.get(userKey);
            Entity originalToken = txn.get(tokenKey);
            if (user == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("User does not exists!").build();
            }
            String hashedPWD = user.getString("user_pwd");
            if (hashedPWD.equals(DigestUtils.sha512Hex(data.password)) && (token.tokenID.equals(originalToken.getString("user_token_ID")))) {
                user = Entity.newBuilder(userKey)
                        .set("user_name", user.getString("user_name"))
                        .set("user_pwd", DigestUtils.sha512Hex(data.newPassword))
                        .set("user_email", user.getString("user_email"))
                        .set("user_typeOfAccount", user.getString("user_typeOfAccount"))
                        .set("user_phone", user.getString("user_phone"))
                        .set("user_mobile_phone", user.getString("user_mobile_phone"))
                        .set("user_occupation", user.getString("user_occupation"))
                        .set("user_work_place", user.getString("user_work_place"))
                        .set("user_address", user.getString("user_address"))
                        .set("user_nif", user.getString("user_nif"))
                        .set("user_role", user.getString("user_role"))
                        .set("user_state", user.getString("user_state"))
                        .set("user_creation_time", user.getTimestamp("user_creation_time"))
                        .build();
                txn.put(user);
                LOG.info("User password updated for user: ");
                txn.commit();
                return Response.ok(token).build();
            } else {
                txn.rollback();
                return Response.status(Response.Status.FORBIDDEN).entity("Token Error!").build();
            }
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }

    }
}
