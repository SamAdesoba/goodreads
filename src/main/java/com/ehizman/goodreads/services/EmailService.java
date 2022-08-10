package com.ehizman.goodreads.services;

import com.ehizman.goodreads.models.MailResponse;
import com.ehizman.goodreads.models.VerificationMessageRequest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.util.concurrent.CompletableFuture;

public interface EmailService {
    CompletableFuture<MailResponse> sendHtmlMail(VerificationMessageRequest messageRequest) throws UnirestException;
    CompletableFuture<MailResponse> sendSimpleMail(VerificationMessageRequest messageRequest) throws UnirestException;
}
