package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;

import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.AdditionalData;
import pt.unl.fct.di.apdc.firstwebapp.util.AdditionalDataForOthers;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;
import javax.ws.rs.core.Response.Status;

@Path("/additional")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class AdditionalInfoResource {

    public enum UserType {
        USER(1),
        GBO(2),
        GS(3),
        SU(4);

        private int type;

        UserType(int type) {
            this.type = type;
        }

        public int getType() {
            return type;
        }
    }

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public AdditionalInfoResource() {
        // Nothing to be done here
    }

    @POST
    @Path("/info")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addInfoToUser(AdditionalData data, @Context HttpHeaders headers) {

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
                return Response.status(Status.BAD_REQUEST).entity("User does not exists!").build();
            }
            if (token.tokenID.equals(originalToken.getString("user_token_ID"))) {
                user = Entity.newBuilder(userKey)
                        .set("user_name", user.getString("user_name"))
                        .set("user_pwd", user.getString("user_pwd"))
                        .set("user_email", user.getString("user_email"))
                        .set("user_typeOfAccount", data.typeOfAccount == "" ? user.getString("user_typeOfAccount") : data.typeOfAccount)
                        .set("user_phone", data.phone == "" ? user.getString("user_phone") : data.phone)
                        .set("user_mobile_phone", data.mobilePhone == "" ? user.getString("user_mobile_phone") : data.mobilePhone)
                        .set("user_occupation", data.occupation == "" ? user.getString("user_occupation") : data.occupation)
                        .set("user_work_place", data.workPlace == "" ? user.getString("user_work_place") : data.workPlace)
                        .set("user_address", data.address == "" ? user.getString("user_address") : data.address)
                        .set("user_nif", data.nif == "" ? user.getString("user_nif") : data.nif)
                        .set("user_role", user.getString("user_role"))
                        .set("user_state", user.getString("user_state"))
                        .set("user_creation_time", user.getTimestamp("user_creation_time"))
                        .build();
                txn.put(user);
                LOG.info("User registered " + token.username);
                txn.commit();
                return Response.ok("{}").build();
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

    @POST
    @Path("/info2")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addInfoToUser2(AdditionalDataForOthers data, @Context HttpHeaders headers) {

        String authTokenHeader = headers.getHeaderString("Authorization");
        String authToken = authTokenHeader.substring("Bearer".length()).trim();
        AuthToken token = g.fromJson(authToken, AuthToken.class);

        Transaction txn = datastore.newTransaction();
        Key setterUserKey = datastore.newKeyFactory().setKind("User").newKey(token.username);
        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", token.username))
                .setKind("User Token").newKey(token.username);
        Key recieverUserKey = datastore.newKeyFactory().setKind("User").newKey(data.username);

        try {
            Entity userSetter = txn.get(setterUserKey);
            Entity originalToken = txn.get(tokenKey);
            Entity userReceiver = txn.get(recieverUserKey);
            if (userSetter == null || userReceiver == null) {
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("User does not exists!").build();
            }
            if (token.tokenID.equals(originalToken.getString("user_token_ID"))) {
                if (UserType.valueOf(userSetter.getString("user_role")).getType() <= UserType.valueOf(userReceiver.getString("user_role")).getType()) {
                    txn.rollback();
                    return Response.status(Response.Status.FORBIDDEN).entity("Permission Denied!").build();
                } else {
                    userReceiver = Entity.newBuilder(recieverUserKey)
                            .set("user_name", data.name == "" ? userReceiver.getString("user_name") : data.name)
                            .set("user_pwd", data.password == "" ? userReceiver.getString("user_pwd") : data.password)
                            .set("user_email", data.email == "" ? userReceiver.getString("user_email") : data.email)
                            .set("user_typeOfAccount", data.typeOfAccount == "" ? userReceiver.getString("user_typeOfAccount") : data.typeOfAccount)
                            .set("user_phone", data.phone == "" ? userReceiver.getString("user_phone") : data.phone)
                            .set("user_mobile_phone", data.mobilePhone == "" ? userReceiver.getString("user_mobile_phone") : data.mobilePhone)
                            .set("user_occupation", data.occupation == "" ? userReceiver.getString("user_occupation") : data.occupation)
                            .set("user_work_place", data.workPlace == "" ? userReceiver.getString("user_work_place") : data.workPlace)
                            .set("user_address", data.address == "" ? userReceiver.getString("user_address") : data.address)
                            .set("user_nif", data.nif == "" ? userReceiver.getString("user_nif") : data.nif)
                            .set("user_role", userReceiver.getString("user_role"))
                            .set("user_state", userReceiver.getString("user_state"))
                            .set("user_creation_time", userReceiver.getTimestamp("user_creation_time"))
                            .build();
                    txn.put(userReceiver);
                    LOG.info("User registered " + token.username);
                    txn.commit();
                    return Response.ok("{}").build();}
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
