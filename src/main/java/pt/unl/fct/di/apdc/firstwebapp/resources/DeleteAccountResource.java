package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;

import java.util.logging.Logger;

import com.google.gson.Gson;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

@Path("/delete")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class DeleteAccountResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public DeleteAccountResource() {
    } // Nothing to be done here

    @POST
    @Path("/account")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response delete(@Context HttpHeaders headers) {

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
            if( user == null ) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).build();
            }

            if(token.tokenID.equals(originalToken.getString("user_token_ID"))) {
                txn.delete(userKey, tokenKey);
                txn.commit();
                return Response.ok().build();
            } else {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).build();
            }
        } catch (Exception e) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
                return Response.status(Status.INTERNAL_SERVER_ERROR).build();
            }
        }
    }

}

