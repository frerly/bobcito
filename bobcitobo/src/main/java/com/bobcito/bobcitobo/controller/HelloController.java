package com.bobcito.bobcitobo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HelloController {

	@GetMapping(value="/")
	public String index() {
		return "Greetings from Spring Boot!";
	}
	

}
