package com.SkytecGamesTest;

import it.tdlight.client.*;
import it.tdlight.jni.TdApi;
import java.util.concurrent.CompletableFuture;
import java.util.Scanner;

public class TelegramAuthHandler implements AuthenticationSupplier<Object> {
    private final String phoneNumber;
    private final String password2FA;
    private final Scanner scanner;

    public TelegramAuthHandler(String phoneNumber, String password2FA) {
        this.phoneNumber = phoneNumber;
        this.password2FA = password2FA;
        this.scanner = new Scanner(System.in);
    }

    @Override
    public CompletableFuture<AuthenticationSupplierResult<Object>> onAuthenticationRequired(TdApi.AuthorizationState state) {
        CompletableFuture<AuthenticationSupplierResult<Object>> future = new CompletableFuture<>();
        
        if (state instanceof TdApi.AuthorizationStateWaitPhoneNumber) {
            System.out.println("Using phone: " + phoneNumber);
            future.complete(AuthenticationSupplierResult.ofPhoneNumber(phoneNumber));
        }
        else if (state instanceof TdApi.AuthorizationStateWaitCode) {
            System.out.println("Enter authentication code: ");
            String code = scanner.nextLine();
            future.complete(AuthenticationSupplierResult.ofAuthenticationCode(code));
        }
        else if (state instanceof TdApi.AuthorizationStateWaitPassword) {
            if (password2FA != null && !password2FA.isEmpty()) {
                System.out.println("Using provided 2FA password");
                future.complete(AuthenticationSupplierResult.ofPassword(password2FA));
            } else {
                System.out.println("Enter 2FA password: ");
                String password = scanner.nextLine();
                future.complete(AuthenticationSupplierResult.ofPassword(password));
            }
        }
        else {
            future.complete(AuthenticationSupplierResult.ofError("Unexpected authorization state: " + state.getClass().getName()));
        }
        
        return future;
    }
} 