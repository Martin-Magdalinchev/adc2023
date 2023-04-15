//package pt.unl.fct.di.apdc.firstwebapp.filters;
//
//import java.io.IOException;
//
//import javax.ws.rs.container.ContainerRequestContext;
//import javax.ws.rs.container.ContainerResponseContext;
//import javax.ws.rs.container.ContainerResponseFilter;
//import javax.ws.rs.ext.Provider;
//
//@Provider
//public class AdditionalResponseHeadersFilter implements ContainerResponseFilter {
//
//	public AdditionalResponseHeadersFilter() {
//	}
//
//	@Override
//	public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
//			throws IOException {
//		responseContext.getHeaders().add("Access-Control-Allow-Methods", "HEAD,GET,PUT,POST,DELETE,OPTIONS");
//		responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
//		responseContext.getHeaders().add("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization");
//		//responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
//	}
//}
package pt.unl.fct.di.apdc.firstwebapp.filters;

import java.io.IOException;
import java.util.logging.Logger;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

public class AdditionalResponseHeadersFilter implements ContainerResponseFilter {
	private static final Logger LOG = Logger.getLogger(AdditionalResponseHeadersFilter.class.getName());

	public AdditionalResponseHeadersFilter() {

	}

	@Override
	public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
		if (!requestContext.getRequest().getMethod().equals("OPTIONS")) {
			LOG.warning("Adding headers to non-OPTIONS request");
			responseContext.getHeaders().remove("Access-Control-Allow-Origin");
			responseContext.getHeaders().add("Access-Control-Allow-Methods", "HEAD,GET,PUT,POST,DELETE,OPTIONS");
			responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
			responseContext.getHeaders().add("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With");
			responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
		}
	}

}
