package com.shashank.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shashank.Exception.InvaliIdException;
import com.shashank.Repository.BookRepository;
import com.shashank.model.Book;

@Service
public class BookServiceImpl implements BookService {

	@Autowired
	private BookRepository bookRepository;

	@Override
	@Transactional
	public List<Book> getAllBooks() {
		return bookRepository.findAll();
	}

	@Override
	public Long saveBook(Book book) {
		return bookRepository.save(book).getBookId();
	}

	@Override
	public Book getSingleBook(Long bookId) {
		return bookRepository.findById(bookId)
				.orElseThrow(() -> new InvaliIdException("Supplied id : " + bookId + " is invalid."));
	}

	@Override
	public Book getBookByBookName(String bookName) {
		return bookRepository.getBookByBookName(bookName);
	}

}
