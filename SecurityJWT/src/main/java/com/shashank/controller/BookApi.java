package com.shashank.controller;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.shashank.dto.ResponseBuilder;
import com.shashank.model.Book;
import com.shashank.service.BookService;

import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping("/api")
public class BookApi {

	@Autowired
	private BookService bookService;

	@Autowired
	private MessageSource messageSource;

	@RequestMapping(value = "/fetch-books", method = RequestMethod.GET, produces = "application/json")
	@ApiOperation(value = "Get operation to get all the books present in database", notes = "Get operation to get all the books present in database", response = ResponseBuilder.class)
	public ResponseEntity<?> fetchAllBooks() {
		try {
			// This will return all books from the database

			return new ResponseEntity<>(new ResponseBuilder.Builder().status(1)
					.message(messageSource.getMessage("success.all.book.fetched", null, null, null))
					.data(bookService.getAllBooks()).build(), HttpStatus.OK);
		} catch (Exception ex) {
			String errorMessage;
			errorMessage = ex + " <== error";
			return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@RequestMapping(value = "/book", method = RequestMethod.POST, produces = "application/json")
	public ResponseEntity<?> saveBook(@Valid @RequestBody Book book) {
		try {

			// This will save book data into db
			return new ResponseEntity<>(new ResponseBuilder.Builder().status(1).message(messageSource
					.getMessage("success.book.save", new Object[] { bookService.saveBook(book) }, null, null)).build(),
					HttpStatus.OK);
		} catch (Exception ex) {
			String errorMessage;
			errorMessage = ex + " <== error";
			return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@RequestMapping(value = "/book/{bookId}", method = RequestMethod.GET, produces = "application/json")
	public ResponseEntity<?> getSingleBookData(@PathVariable(value = "bookId") @NotNull Long bookId) {
		try {

			// This will return single data with the supplied id
			return new ResponseEntity<>(new ResponseBuilder.Builder().status(1)
					.message(messageSource.getMessage("success.single.book.data", null, null, null))
					.data(bookService.getSingleBook(bookId)).build(), HttpStatus.OK);
		} catch (Exception ex) {
			String errorMessage;
			errorMessage = ex + " <== error";
			return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@RequestMapping(value = "/book-by-name/{bookName}", method = RequestMethod.GET, produces = "application/json")
	public ResponseEntity<?> getBookByBookName(@PathVariable(value = "bookName") @NotNull String bookName) {
		try {

			// This will return single data with the supplied id
			return new ResponseEntity<>(new ResponseBuilder.Builder().status(1)
					.message(messageSource.getMessage("success.single.book.data", null, null, null))
					.data(bookService.getBookByBookName(bookName)).build(), HttpStatus.OK);
		} catch (Exception ex) {
			String errorMessage;
			errorMessage = ex + " <== error";
			return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

}
