package com.ehizman.goodreads.services;

import com.ehizman.goodreads.controllers.requestsAndResponses.AccountCreationRequest;
import com.ehizman.goodreads.controllers.requestsAndResponses.UpdateRequest;
import com.ehizman.goodreads.dtos.UserDto;
import com.ehizman.goodreads.exceptions.GoodReadsException;
import com.ehizman.goodreads.models.User;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.util.List;
import java.util.concurrent.ExecutionException;

public interface UserService {
    UserDto createUserAccount(String host, AccountCreationRequest accountCreationRequest) throws GoodReadsException, UnirestException, ExecutionException, InterruptedException;
    UserDto findUserById(String userId) throws GoodReadsException;
    List<UserDto> findAll();
    UserDto updateUserProfile(String id, UpdateRequest updateRequest) throws GoodReadsException;
    User findUserByEmail(String email) throws GoodReadsException;

    void verifyUser(String token) throws GoodReadsException;
}
