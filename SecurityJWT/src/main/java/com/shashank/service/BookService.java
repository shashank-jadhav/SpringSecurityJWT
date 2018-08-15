package com.shashank.service;

import java.util.List;

import com.shashank.model.Book;

public interface BookService {

	public List<Book> getAllBooks();

	public Long saveBook(Book book);

	public Book getSingleBook(Long bookId);

	public Book getBookByBookName(String bookName);
}
