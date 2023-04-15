package pt.unl.fct.di.apdc.firstwebapp.filters;

import java.io.IOException;
import java.util.logging.Logger;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

@Provider
public class OptionsResponseFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(OptionsResponseFilter.class.getName());

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (requestContext.getRequest().getMethod().equals("OPTIONS")) {
            LOG.warning("Handling OPTIONS request");
            requestContext.abortWith(Response.status(Response.Status.NO_CONTENT)
                    .header("Access-Control-Allow-Methods", "HEAD,GET,PUT,POST,DELETE,OPTIONS")
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
                    .header("Access-Control-Allow-Credentials", "true")
                    .build());
        }
    }
}
