package io.github.kilmajster.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import static io.github.kilmajster.keycloak.UsernamePasswordAttributeFormConfiguration.USER_ATTRIBUTE;
import static io.github.kilmajster.keycloak.UsernamePasswordAttributeFormConfiguration.configPropertyOf;

import org.keycloak.authentication.AuthenticationFlowContext;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;

import org.keycloak.models.UserModel;

import org.keycloak.services.ServicesLogger;





public class UsernamePasswordAttributeForm extends UsernamePasswordForm implements Authenticator {

    protected static ServicesLogger log = ServicesLogger.LOGGER;

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {

        return super.challenge(context, null, null);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return super.challenge(context, formData);
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.info("Form Data");
    log.info(formData.toString());
    String username =context.getHttpRequest().getDecodedFormParameters().getFirst("username");
    String userAttributeName = configPropertyOf(context, USER_ATTRIBUTE);
    UserModel user = context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(), userAttributeName,username ).findFirst().orElse(null);
    if (user != null) {
        log.info("user found by cedula:");
        log.info(user.getAttributes().toString());
        formData.remove("username");
        formData.add("username", user.getUsername());
    }
    return super.validateForm(context, formData);
    }
}
