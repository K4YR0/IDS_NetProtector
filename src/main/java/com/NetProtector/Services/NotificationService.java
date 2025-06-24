package com.NetProtector.Services;

import com.NetProtector.Models.Alert;

public interface NotificationService {
    /** Deliver a single alert-derived notification; non-blocking. */
    void notify(Alert alert);

    default void start() {}
    default void stop() {}
}