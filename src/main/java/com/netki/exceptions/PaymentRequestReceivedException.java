package com.netki.exceptions;

import org.bitcoin.protocols.payments.Protos;

public class PaymentRequestReceivedException extends Exception {

    private Protos.PaymentRequest paymentRequest = null;

    public PaymentRequestReceivedException(Protos.PaymentRequest pr) {
        this.paymentRequest = pr;
    }

    public Protos.PaymentRequest getPaymentRequest() {
        return this.paymentRequest;
    }
}
