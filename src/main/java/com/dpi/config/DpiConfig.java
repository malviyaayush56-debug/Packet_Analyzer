package com.dpi.config;

import com.dpi.service.PcapReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DpiConfig {

    @Bean
    public PcapReader pcapReader() {
        return new PcapReader();
    }
}
