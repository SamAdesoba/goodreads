package com.ehizman.goodreads.events;

import com.ehizman.goodreads.models.MailResponse;
import com.ehizman.goodreads.models.VerificationMessageRequest;
import com.ehizman.goodreads.services.EmailService;
import com.mashape.unirest.http.exceptions.UnirestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Arrays;
import java.util.concurrent.ExecutionException;

@Component
@Slf4j
public class SendMessageEventListener {
    @Qualifier("mailgun_sender")
    @Autowired
    private EmailService emailService;
    @Autowired
    Environment env;
    @Autowired
    private TemplateEngine templateEngine;

    @EventListener
    public void handleSendMessageEvent(SendMessageEvent event) throws UnirestException, ExecutionException, InterruptedException {
        VerificationMessageRequest messageRequest = (VerificationMessageRequest) event.getSource();
        log.info("Domain Url -->{}", messageRequest.getDomainUrl());
        log.info("Token -->{}", messageRequest.getVerificationToken());

        String verificationLink = messageRequest.getDomainUrl()+"api/v1/auth/verify/"+messageRequest.getVerificationToken();
        log.info("Verification Link --> {}",verificationLink );

        log.info("Message request --> {}",messageRequest);
        Context context = new Context();
        context.setVariable("user_name", messageRequest.getUsersFullName().toUpperCase());
        context.setVariable("verification_token", verificationLink);
        if (Arrays.asList(env.getActiveProfiles()).contains("dev")){
            log.info("Message Event -> {}", event.getSource());
            messageRequest.setBody(templateEngine.process("registration_verification_mail.html", context));
            MailResponse mailResponse = emailService.sendHtmlMail(messageRequest).get();
        } else{
            messageRequest.setBody("https://google.com");
            MailResponse mailResponse = emailService.sendSimpleMail(messageRequest).get();

        }
    }
}
