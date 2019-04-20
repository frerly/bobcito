package com.bobcito.bobcitobo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HelloController {

	@RequestMapping(value="/")
	public String index() {
		return "Greetings from Spring Boot!";
	}
	

}
