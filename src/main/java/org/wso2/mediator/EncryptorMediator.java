package org.wso2.mediator;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class EncryptorMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(EncryptorMediator.class);

    public boolean mediate(MessageContext context) {

        String payload = getProperty(context, "Payload");
        if (payload == null || payload.length() < 1) {
            return completeProcess(context, "Payload is empty.", "fail");
        } else {
            String encryptionKey = getProperty(context, "SecretKey");
            String method = getProperty(context, "Method");
            process(context, payload, encryptionKey, method);
        }
        return true;
    }

    private boolean process(MessageContext ctx, String payload, String encryptionKey, String method) {

        String respondPayload;

        EncryptorAES encryptor = new EncryptorAES();
        if (method.equals("Encrypt")) {
            respondPayload = encryptor.encrypt(payload, encryptionKey);
            return completeProcess(ctx, respondPayload, "success");
        } else {
            if (encryptionKey != null && !encryptionKey.equals("NULL")) {
                respondPayload = encryptor.decrypt(payload, encryptionKey);
                return completeProcess(ctx, respondPayload, "success");
            } else {
                return completeProcess(ctx, "Encryption key  is invalid.", "fail");
            }
        }
    }

    private boolean completeProcess(MessageContext context, String message, String state) {

        setState(context, state);
        setMessage(context, message, state);
        return true;
    }

    private String getProperty(MessageContext context, String propertyKey) {

        if (context.getProperty(propertyKey) != null) {
            return context.getProperty(propertyKey).toString();
        } else {

            log.error("Provide value for " + propertyKey + " is null");
            return null;
        }

    }

    private void setState(MessageContext context, String state) {

        context.setProperty("success", state);
    }

    private void setMessage(MessageContext context, String Message, String state) {

        if (state == "success") {
            context.setProperty("resultPayload", Message);
        } else {
            log.error(Message);
            context.setProperty("errorMessage", Message);
        }
    }

}
