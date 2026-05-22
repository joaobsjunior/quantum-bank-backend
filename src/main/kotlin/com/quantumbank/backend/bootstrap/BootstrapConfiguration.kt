package com.quantumbank.backend.bootstrap

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.time.Clock

@Configuration
class BootstrapConfiguration {

    @Bean
    fun bootstrapClock(): Clock = Clock.systemUTC()
}
