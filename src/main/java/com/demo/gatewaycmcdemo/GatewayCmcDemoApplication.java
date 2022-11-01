package com.demo.gatewaycmcdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
@SpringBootApplication
@EnableDiscoveryClient
public class GatewayCmcDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayCmcDemoApplication.class, args);
	}

}
