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
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LogOutResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public LogOutResource() {
    } // Nothing to be done here

    @POST
    @Path("/v1")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response logout(@Context HttpHeaders headers) {

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
                txn.delete(tokenKey);
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

}

